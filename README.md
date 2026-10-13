# BrandSentinel — Enterprise Brand Protection & Threat Mitigation Platform

BrandSentinel is a responsive, accessible web application designed for continuous brand protection against unauthorized social account squatting, counterfeit mobile applications, and domain impersonation.

---

## 🌟 Key Recreated Features

1. **Dark Navy Sidebar (`#0B132B`)**:
   - Modern BrandSentinel emblem with glowing shield/radar styling and "Brand Shield AI" subtitle.
   - Primary navigation:
     - `Brand profile` (IP & trademark registry)
     - `Scan & review` (Core monitoring workspace with active pulse indicator)
     - `API connections` (Channel telemetry integration hub)
     - `Reports` (Threat analytics & remediation metrics)
   - Real-time protection metrics summary widget and system status indicator (`v1.4.2-preview`).

2. **Top Bar**:
   - **Northstar Brand Selector**: Dropdown to switch monitored brands (Northstar Technologies, Northstar Athletics, Northstar FinTech).
   - **Sample-Data Badge**: Prominent `FICTIONAL SAMPLE DATA | Demo Sandbox` tag.
   - **Live Date Display**: Dynamically formatted current date.
   - **User Menu**: Profile circle (`VK`), name `Vinay Kumar`, role `Security Lead`, and mock profile/settings dropdown.
   - **Responsive Hamburger Toggle**: Off-canvas drawer support on mobile viewports.

3. **Heading Section**:
   - **“Connect. Scan. Verify.”** high-contrast banner with context description.
   - Action controls for exporting telemetry and adding data sources.

4. **Three-Step Progress Indicator**:
   - **Step 1: Connect Source** (Connected state, 3 active feeds).
   - **Step 2: Scan & Detect** (Active scanning phase indicator with animated radar pulse).
   - **Step 3: Verify & Remediate** (Actionable pending queue indicator).

5. **Scan Control Bar**:
   - Target account handle, app package, or domain input field.
   - Multi-source selector (All Sources, Instagram, X/Twitter, Apple App Store, Google Play, TikTok, Domain Registry).
   - **"Scan source"** primary button with simulated scanning animation, progress dialog, and automatic finding generation.

6. **Results Table**:
   - Filter tabs: **All**, **Social**, and **Apps** with dynamic count badges.
   - Live search input and risk severity dropdown (Critical, High, Medium).
   - Interactive table rows with checkbox support, match confidence bars, and risk tags.
   - Click-to-inspect row selection highlighting.

7. **Selected-Result Evidence Card**:
   - Detailed side-by-side comparison between **Detected Impersonator** and **Official Northstar Asset**.
   - Vector similarity scores, visual palette matches, and identified violations checklist.
   - Forensic host and IP telemetry details.
   - Simulated remediation actions: **Simulate Takedown** and **Whitelist Handle**.

8. **Right-Side “Connect a data source” Panel**:
   - 6 platform connectors (Instagram Graph API, X API v2, Apple App Store Connect, Google Play Developer API, TikTok for Business, Domain Registry).
   - Real-time connection status toggles, rate limits, and mock sandbox modal.

---

## 🗄️ Persistence Layer & Database Migrations

BrandSentinel features persistent relational storage and versioned database migrations powered by SQLAlchemy and SQLite (`data/brandsentinel.db`).

### Supported Entities (11 Core Models):
1. **Users**: User profiles with security roles (`security_lead`, `analyst`, `admin`).
2. **Organizations**: Multi-tenant organizations with sample data segregation (`is_sample`).
3. **Memberships**: User-to-Organization relationships with role-based scoping.
4. **Brands**: Organization-scoped brand identities with names, aliases, logos, and industries.
5. **OfficialAssets**: Exact source-scoped official domains, social channels, and app packages.
6. **SourceConnections**: Monitoring telemetry feed configurations with mock sandbox state.
7. **Scans**: Scans initiated by users against target queries across source platforms.
8. **Candidates**: Discovered entities evaluated for potential trademark infringement.
9. **Detections**: Evaluated brand threat findings with risk scores, match vectors, and status.
10. **Reviews**: Analyst review actions (`flagged`, `takedown_sent`, `whitelisted`, `dismissed`).
11. **AuditEvents**: Organization-scoped audit trail logging all modifications with IP addresses.

### Migration Management:
Migrations are tracked in the `schema_migrations` table and executed via:
```bash
python -m db.migrations.migrator
```
- `v001_initial_schema.py`: Creates all 11 core tables and indices.
- `v002_add_publisher_indices.py`: Adds multi-tenant query indices.

### Official Identity Verification Rule:
> **Core Security Principle:** Official identity is established **only** via exact source-scoped identifiers and stable platform channel/app IDs. **Never establish official identity from a similar name or logo alone.** Candidates mimicking brand names or visual assets with different stable IDs are strictly classified as unauthorized impersonators.

---

## 🚀 Running the Application

### Start Web Server
```bash
python app.py
```
Open your browser to:
```
http://127.0.0.1:5000/
```

### Run Automated Tests
```bash
# Run persistence, migration, validation, and matcher tests (12 tests)
python test_persistence.py

# Run web and API integration tests (7 tests)
python test_app.py

# Run environment configuration tests (10 tests)
python test_config.py

# Run authentication, MFA, session, and security tests (11 tests)
python test_auth.py

# Run server-side authorization, RBAC, and multi-tenant isolation tests (12 tests)
python test_authorization.py

# Run source connectors, encrypted vault, YouTube, and key isolation tests (13 tests)
python test_sources.py

# Run entire comprehensive test suite (65 tests)
python -m unittest discover -s . -p "test_*.py"
```

---

---

## 📡 Multi-Platform API Connections & Reusable Connector Architecture (Phase 6)

BrandSentinel features an expandable, schema-driven multi-platform connector hub allowing organization owners to independently configure and maintain multiple connection instances across major messaging platforms, social networks, and app stores.

### 1. Platform Catalog & Integration Matrix (Zero Fabricated Coverage)

Every platform card clearly distinguishes its status from among **7 explicit states**:
`Not configured`, `Connected`, `Limited access`, `Expired`, `Rate limited`, `Unavailable`, and `Coming later`.

| Platform | Authentication Method | Supported Capabilities | Access Limitations & Operational Boundaries | Status |
| :--- | :--- | :--- | :--- | :---: |
| **YouTube** | Server-side Google Cloud API Key | `searchCandidates`, `lookupAsset` | Public video/channel search and lookup within Google Cloud project quotas (10,000 units/day). Private channel audits require OAuth 2.0. | **Connected / Configurable** |
| **Telegram** | Bot API Token | `readAuthorizedChannel`, `lookupAsset` | **Strict Boundary Enforced**: Bot API access is limited exclusively to chats and public channels where the bot has been added. Cannot search all global Telegram users or scrape unjoined private groups. | **Connected / Configurable** |
| **Facebook** | Meta Graph OAuth Access Token | `readManagedPages`, `lookupAsset` | **Strict Boundary Enforced**: Meta Graph API access is restricted to verified managed Pages and approved developer permissions (`pages_read_engagement`). Cannot execute arbitrary broad profile searches across Facebook. | **Connected / Configurable** |
| **Google Play Store** | Service Account JSON / Package Import | `lookupAsset`, `importRecords` | **Strict Boundary Enforced**: The Google Play Developer API (Android Publisher API) is designed exclusively for developer account app management, not a public search engine. Discovery is powered by developer package manifests and authorized data feeds. | **Connected / Configurable** |
| **Apple App Store** | Documented iTunes Search API (Zero Keys) | `searchPublicStore`, `lookupAsset` | Uses Apple's documented public iTunes Search & Lookup API across multi-country regional storefronts (`US`, `GB`, `DE`, `FR`, `JP`, etc.). No private credentials required for store discovery. | **Connected / Configurable** |
| **Instagram** | Meta Business OAuth | `lookupAsset` | Requires Meta Business App Verification and active page linking. Live scanning is strictly disabled. | **Coming later** |
| **LinkedIn** | Community Management OAuth | `lookupAsset` | Requires verified LinkedIn Company Page administrator approval and commercial developer partnership. | **Coming later** |
| **X (Twitter)** | Developer Bearer Token | `searchCandidates`, `lookupAsset` | X API v2 search requires Basic or Pro paid developer tier; free tier is restricted to write-only operations. | **Coming later** |
| **TikTok** | Commercial Content API | `lookupAsset` | Requires business entity validation and approved commercial API audit. | **Coming later** |
| **Discord** | Application Bot Token | `readAuthorizedChannel` | Bot API can only monitor servers (guilds) where the bot has been explicitly invited with read permissions. | **Coming later** |

---

### 2. Platform-Specific Setup Guides & Authentication Schemas

Forms are dynamically generated from each connector's `config_schema` rather than forcing a generic API key input:

#### A. YouTube Data API v3
- **Authentication**: Server-side Google Cloud API Key (`AIzaSy...`).
- **Required Cloud Scopes**: YouTube Data API v3 enabled in Google Cloud Console.
- **Quota & Error Handling**:
  - `INVALID_CREDENTIALS`: Detects HTTP 400 `keyInvalid` reason with clear actionable remediation.
  - `QUOTA_EXCEEDED`: Detects HTTP 403 `quotaExceeded` or `dailyLimitExceeded` and marks status `Rate limited`.
  - `TIMEOUT`: Provider latency > 5.0s is reported cleanly without application crashes.
  - `OUTAGE`: HTTP 5xx or connection drops mark status `Unavailable` with error isolation.

#### B. Telegram Bot API
- **Authentication**: Telegram Bot Token (`123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`).
- **Configuration**: Monitored channel / chat identifiers (e.g. `@northstar_official`, `@northstar_alerts`, `-1001234567890`).
- **Accessible Assets Display**: On successful connection, queries `getMe` and displays the verified bot username and accessible chats.
- **Honesty Statement**: Telegram Bot tokens cannot search all Telegram accounts or read arbitrary private groups.

#### C. Facebook (Meta Graph API)
- **Authentication**: Meta Graph API User or Page Access Token (`EAA...`).
- **Permissions**: Inspects granted scopes via `/me/permissions` (e.g. `pages_read_engagement`, `pages_show_list`).
- **Accessible Assets Display**: Queries `/me/accounts` to display verified managed Pages and granted permission scopes.
- **Honesty Statement**: Does not claim unrestricted scanning of arbitrary private Facebook profiles or groups.

#### D. Google Play Store
- **Authentication**: Google Cloud Service Account JSON key or authorized package manifest import.
- **Developer Package Import**: Allows organization owners to supply structured package manifests (`[{"package_name": "com.northstar.mobile", "publisher_id": "pub-..."}]`).
- **Honesty Statement**: Clarifies that Android Publisher API credentials do not provide general public search capabilities across third-party apps.

#### E. Apple App Store
- **Authentication**: None required for public storefront discovery (uses official iTunes Search and Lookup API).
- **Configuration**: Regional storefront selection (`US`, `GB`, `DE`, `FR`, `JP`, etc.).
- **Honesty Statement**: Public store discovery does not request unnecessary private developer credentials.

---

### 3. Reusable Connector Architecture

The codebase defines a unified connector registry (`connectors.py`) preventing scattered platform-specific conditions:
- **`BaseConnector` ABC**:
  - `validate_config(config)`: Schema validation before saving credentials.
  - `test_connection(credentials, config)`: Upstream connection test returning `ConnectionResult`.
  - `discover_candidates(query, credentials, config)`: Candidate threat discovery.
  - `lookup_asset(identifier, credentials, config)`: Exact asset resolution.
  - `normalize_evidence(raw_data)`: Standardizes evidence into `NormalizedCandidate`.
  - `disconnect(credentials, config)`: Provider revocation hook where supported.
- **`NormalizedCandidate` Standard Schema**:
  - `provider`: Unique provider ID.
  - `external_id`: Stable source-scoped platform identifier.
  - `asset_type`: `social_account`, `mobile_app`, `domain`, `bot_channel`.
  - `display_name`: Account, app, or channel title.
  - `handle_or_package`: Exact handle or package identifier.
  - `description`: Profile bio or app summary.
  - `logo_url`: Remote avatar/icon reference.
  - `publisher_id` / `publisher_name`: Verified publisher entity when available.
  - `provenance`: Collection endpoint, query, timestamp, and response metadata.
  - `missing_evidence_indicators`: Explicit disclosure of telemetry absent due to provider boundaries.
- **`ConnectorRegistry`**:
  - Dynamically registers connector adapters.
  - New connectors can be introduced at runtime with zero modifications to the detection engine.

---

### 4. Multi-Source Federated Scanning & Partial Failure Isolation

BrandSentinel features a multi-source scanning coordinator (`POST /api/scan/multi`):
- **Federated Execution**: Concurrently evaluates target queries across all selected source connectors.
- **Partial Failure Resilience**: When an upstream provider times out or throws HTTP 503 / 504, the failure is isolated to that provider. Results from successful sources are **strictly preserved** without aborting the scan.
- **Candidate Deduplication**: Candidates discovered across multiple feeds are deduplicated by provider and stable `external_id`.
- **Exact Official Identity Matching**: Discovered entities are cross-referenced against the organization's official assets using exact source-scoped matching (`db/matcher.py`).
- **Multi-Platform Intelligence Breakdown**:
  - Metrics overview: Sources queried, total candidates, official matches excluded, impersonators flagged, and inconclusive count.
  - Telemetry coverage pills: Real-time per-source breakdown showing candidates discovered and infringements identified.
  - Partial failure alert banner: Clearly highlights unresponsive sources while confirming preserved results.

---

### 5. Managed Credential Vault & Zero Client-Side Secret Exposure

- **AES-128-CBC + HMAC-SHA256 (Fernet) Encryption at Rest**:
  - Stored credentials in `source_connections.encrypted_credentials` contain only ciphertext.
  - Encryption key (`CREDENTIAL_ENCRYPTION_KEY`) is stored separately in cloud secret storage.
- **Zero Browser Secret Exposure**:
  - Saved credentials are **never returned to the browser** in any API response or modal payload.
  - Secret input fields are cleared immediately after saving.
  - Visibility toggling is permitted **only for newly typed, unsaved input**.
  - Replacement and deletion are supported without revealing existing stored keys.
- **Owner-Only RBAC & Tenant Isolation**:
  - Only authenticated organization users with the `owner` role can create, test, replace, or delete connection instances.
  - Credentials and connection instances are strictly scoped to `organization_id == g.org_id`.



## 🛡️ Server-Side Authorization & Multi-Tenant Isolation

BrandSentinel enforces a strict **Deny-by-Default** authorization model with cryptographically verified server-side session identity and absolute multi-tenant data isolation.

### 1. Role-Based Access Control (RBAC)
Every route, action, report, export, and administrative endpoint validates explicit granular permissions via the `@require_permission` decorator:
- **`Owner`**: Organization governance, member invitations, role promotions/demotions, source credentials, and full audit exports.
- **`Admin`**: Monitored brand identity definitions, official asset registries, and threat investigation workflows.
- **`Analyst`**: Daily operational triage, running new scans, investigating candidates, adding notes, and submitting review verdicts.
- **`Viewer`**: Permitted read-only access to brand configurations, findings, and high-level summary metrics.

---

### 2. Comprehensive Permission Matrix

| Capability / Action | Permission Key | Owner | Admin | Analyst | Viewer |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **View Brands & Assets** | `brand:read` | ✅ | ✅ | ✅ | ✅ |
| **Create Brand Identity** | `brand:create` | ✅ | ✅ | ❌ | ❌ |
| **Update Brand Identity** | `brand:update` | ✅ | ✅ | ❌ | ❌ |
| **Register Official Asset** | `asset:create` | ✅ | ✅ | ❌ | ❌ |
| **Delete Official Asset** | `asset:delete` | ✅ | ✅ | ❌ | ❌ |
| **View Findings & Telemetry** | `detection:read` | ✅ | ✅ | ✅ | ✅ |
| **Review Verdict / Takedown** | `detection:review` | ✅ | ✅ | ✅ | ❌ |
| **Trigger Platform Scans** | `scan:run` | ✅ | ✅ | ✅ | ❌ |
| **View Connected Sources** | `source:read` | ✅ | ✅ | ✅ | ✅ |
| **Manage Source Credentials** | `source:manage` | ✅ | ❌ | ❌ | ❌ |
| **View Reports Dashboard** | `report:view` | ✅ | ✅ | ✅ | ✅ |
| **Export Summary / KPIs** | `export:summary` | ✅ | ✅ | ✅ | ✅ |
| **Export Raw Forensics / Telemetry** | `export:telemetry` | ✅ | ✅ | ✅ | ❌ |
| **View Audit Trail** | `audit:read` | ✅ | ✅ | ❌ | ❌ |
| **Export Compliance Audit Logs** | `audit:export` | ✅ | ❌ | ❌ | ❌ |
| **View Organization Members** | `member:read` | ✅ | ✅ | ✅ | ✅ |
| **Invite New Members** | `member:invite` | ✅ | ❌ | ❌ | ❌ |
| **Update Member Roles** | `member:update_role` | ✅ | ❌ | ❌ | ❌ |
| **Remove Members** | `member:remove` | ✅ | ❌ | ❌ | ❌ |

---

### 3. Explicit Report & Export Permissions
To protect operational intelligence and forensic integrity:
- **`export:summary` (`/api/reports/export?format=csv|json`)**: Aggregated executive metrics, detection severity breakdown, and high-level resolution stats. Available to all roles including **Viewer**.
- **`export:telemetry` (`/api/reports/export?format=csv|json&type=telemetry`)**: Complete threat discovery logs, candidate metadata, platform channel IDs, and raw forensic vector similarity scores. Restricted to **Analyst, Admin, Owner**; denied to **Viewer** (HTTP 403 `FORBIDDEN`).
- **`audit:read` (`/api/audit`)**: Real-time audit log viewer showing administrative changes, IP origins, and timestamps. Permitted to **Admin** and **Owner**; denied to **Analyst** and **Viewer**.
- **`audit:export` (`/api/audit/export?format=csv|json`)**: Cryptographic compliance log archive containing historical administrative governance records. Strictly reserved for **Owner**; denied to **Admin, Analyst, Viewer** (HTTP 403 `FORBIDDEN`).

---

### 4. Tenant Scoping & Isolation Architecture
1. **Zero Client Trust**:
   - The server **never** trusts client-supplied `user_id`, `role`, or `organization_id` in request bodies or query params.
   - User identity is cryptographically validated via the authenticated session token.
   - Active organization membership and roles are resolved directly from the database on every request.
   - Any attempt to supply an unauthorized `X-Organization-Id` returns HTTP 403 `ORGANIZATION_ACCESS_DENIED`.
2. **Strict Query Scoping**:
   - Every database query for brands, assets, scans, candidates, detections, reviews, source connections, and audit events is strictly filtered by `organization_id == g.org_id`.
   - Modifying a target identifier in an API call (e.g., attempting to access or modify an entity belonging to Org Beta while authenticated in Org Alpha) results in HTTP 404 `NOT_FOUND` or HTTP 403 `FORBIDDEN`, completely preventing cross-tenant information leakage or tampering.
3. **Governance & Anti-Lockout Protections**:
   - **Last Owner Protection (`LAST_OWNER_PROTECTION`)**: The system blocks any demotion or removal of an organization's sole remaining owner with HTTP 400.
   - **Self-Modification Prevention (`SELF_MODIFICATION_FORBIDDEN` / `SELF_REMOVAL_FORBIDDEN`)**: Administrators cannot alter or revoke their own roles to prevent accidental privilege loss or circumvention.
   - **Immediate Session Invalidation**: Whenever a user's role is updated or their membership is revoked, `revoke_all_user_sessions` terminates all existing active sessions immediately, ensuring demotions cannot be bypassed with existing session tokens.
4. **Secret-Safe Audit Logging**:
   - All administrative actions are recorded in the `audit_events` table with actor ID, organization ID, and IP address.
   - Payloads are recursively scrubbed: keys matching `password`, `secret`, `token`, `key`, `credential`, `hash`, or `auth` are replaced with `[REDACTED]` prior to storage.


## 🔐 Enterprise Authentication & Access Control

BrandSentinel implements production-grade authentication and access control utilizing maintained, industry-standard cryptographic libraries (`argon2-cffi` and `pyotp`).

### Architecture & Security Controls:
1. **Password Hashing (Argon2id)**:
   - High-memory and parallelism Argon2id parameters (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`).
   - Strict OWASP complexity validation (minimum 10 characters, mixed case, numeric digit, and special character).
   - Zero hardcoded or shipped default administrator passwords.

2. **Server-Validated Sessions & Token Protection**:
   - Persisted in `user_sessions` table with SHA-256 token hashing (`token_hash`). Raw tokens are never stored in the database.
   - Dual-layer expiration: **2-Hour Inactivity Idle Timeout** and **7-Day Absolute Timeout**.
   - Session rotation upon privilege changes to thwart session fixation attacks.
   - Centralized revocation (`/api/auth/logout` and `/api/auth/logout-all`).

3. **Strict Cookie Security (Zero LocalStorage Persistence)**:
   - Session identifiers are transmitted **strictly via HttpOnly cookies** (`brandsentinel_session`).
   - `SameSite=Lax` cookie policy to thwart cross-site request forgery.
   - `Secure=True` enforced automatically in production environments.
   - **Zero tokens stored in browser `localStorage` or `sessionStorage`**.

4. **Multi-Factor Authentication (RFC 6238 TOTP)**:
   - Mandatory TOTP multi-factor authentication for privileged roles (`security_lead`, `admin`, `owner`).
   - Secret generation, standard `otpauth://` provisioning URI generation, and drift-tolerant 6-digit code validation via `pyotp`.
   - MFA challenge tickets are single-use and rate-limited.

5. **CSRF Protection**:
   - Cryptographically bound `csrf_token` per authenticated session.
   - State-mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) require the `X-CSRF-Token` header.

6. **Validated Redirects (Open Redirect Defense)**:
   - Strict sanitization of `next` target paths (`get_safe_redirect`).
   - Neutralizes protocol-relative (`//evil.com`), absolute URLs (`https://attacker.com`), and pseudo-schemes (`javascript:...`) to safe `/` paths.

7. **Database-Backed Rate Limiting**:
   - Throttling on `/api/auth/login`, `/api/auth/register`, `/api/auth/forgot-password`, and `/api/auth/mfa/verify`.
   - 5 failed attempts within a 15-minute window results in temporary IP and account lockouts (HTTP 429 with standard `Retry-After` header).

8. **Verified Onboarding & Recovery**:
   - Single-use SHA-256 hashed email verification tokens.
   - Single-use password reset tokens with mandatory revocation of **all** prior active user sessions upon password reset.

9. **Zero Production Bypass**:
   - Production mode strictly rejects unauthenticated state mutations with HTTP 401.

---

## 🔒 Security & Privacy Notice

- **Fictional Data**: All brand accounts, violation telemetry, and metrics in this application are strictly synthetic sample data.
- **No Live Scraping**: Scanning workflows simulate discovery patterns against local demonstration benchmarks.
- **Zero Credential Persistence**: No third-party API secrets or cleartext user credentials are stored.
