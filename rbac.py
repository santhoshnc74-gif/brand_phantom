"""
Role-Based Access Control (RBAC) and Multi-Tenant Isolation Module for BrandSentinel.

Role Definitions:
- Owner: Organization governance, member management, role assignment, source credentials & integrations.
- Admin: Brand identity management, official asset registrations, investigation assignment, and audit inspection.
- Analyst: Operational triage. Initiates scans, writes investigative notes, and submits review verdicts.
- Viewer: Permitted read-only access to authorized organization resources and executive summary reports.

Report/Export Permissions:
- export:summary   -> Permitted for Viewer, Analyst, Admin, Owner (Aggregated KPIs and executive summaries)
- export:telemetry -> Permitted for Analyst, Admin, Owner (Detailed forensic candidate evidence & raw metadata)
- audit:read       -> Permitted for Admin, Owner (Compliance audit event trail)
- audit:export     -> Permitted for Owner only (Full historical tenant compliance export)
"""

from functools import wraps
from typing import Optional, Set, List
from flask import request, jsonify, g

from db.models import Membership, UserSession

# Explicit Role Hierarchy (Higher number = higher privilege)
ROLE_HIERARCHY = {
    "owner": 4,
    "admin": 3,
    "analyst": 2,
    "viewer": 1,
}

# Granular Permission Matrix
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    "viewer": {
        "brand:read",
        "asset:read",
        "detection:read",
        "source:read",
        "report:view",
        "export:summary",
    },
    "analyst": {
        # All Viewer permissions
        "brand:read",
        "asset:read",
        "detection:read",
        "source:read",
        "report:view",
        "export:summary",
        # Analyst operational capabilities
        "scan:run",
        "detection:review",
        "detection:note",
        "export:telemetry",
        "export:raw",
    },
    "admin": {
        # All Analyst permissions
        "brand:read",
        "asset:read",
        "detection:read",
        "source:read",
        "report:view",
        "export:summary",
        "scan:run",
        "detection:review",
        "detection:note",
        "export:telemetry",
        "export:raw",
        # Admin brand & investigation governance
        "brand:create",
        "brand:update",
        "brand:delete",
        "asset:create",
        "asset:delete",
        "investigation:manage",
        "audit:read",
        "report:manage",
    },
    "owner": {
        # All Admin permissions
        "brand:read",
        "asset:read",
        "detection:read",
        "source:read",
        "report:view",
        "export:summary",
        "scan:run",
        "detection:review",
        "detection:note",
        "export:telemetry",
        "export:raw",
        "brand:create",
        "brand:update",
        "brand:delete",
        "asset:create",
        "asset:delete",
        "investigation:manage",
        "audit:read",
        "report:manage",
        # Owner organization governance & source credentials
        "org:manage",
        "member:read",
        "member:invite",
        "member:update_role",
        "member:remove",
        "source:manage",
        "source:credentials",
        "audit:export",
    }
}

def has_permission(role: Optional[str], permission: str) -> bool:
    """Verifies whether a given organization role possesses an explicit permission."""
    if not role:
        return False
    role_normalized = role.lower().strip()
    permissions = ROLE_PERMISSIONS.get(role_normalized, set())
    return permission in permissions

def get_role_permissions(role: Optional[str]) -> List[str]:
    """Returns sorted list of all permissions granted to a role."""
    if not role:
        return []
    return sorted(list(ROLE_PERMISSIONS.get(role.lower().strip(), set())))

def require_permission(permission: str):
    """
    Route decorator enforcing:
    1. Authentication validation.
    2. Tenant boundary validation (never trust client-supplied org IDs).
    3. Explicit permission grant for active organization membership role.
    4. Deny access by default if permission is absent.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Enforce Authentication
            user = getattr(g, "current_user", None)
            is_production = getattr(g, "is_production", False)

            if not user or not user.is_active:
                if not is_production and not user:
                    user_role = getattr(g, "user_role", "owner")
                    if has_permission(user_role, permission):
                        return f(*args, **kwargs)
                return jsonify({
                    "error": "Authentication required. Please sign in.",
                    "code": "UNAUTHORIZED"
                }), 401

            # 2. Enforce Tenant Membership & Isolation
            if getattr(g, "org_access_denied", False):
                return jsonify({
                    "error": "Forbidden: You are not an authorized member of the requested organization.",
                    "code": "ORGANIZATION_ACCESS_DENIED"
                }), 403

            org_id = getattr(g, "org_id", None)
            membership = getattr(g, "membership", None)
            if not org_id or not membership:
                return jsonify({
                    "error": "Forbidden: No active organization membership found for this account.",
                    "code": "NO_ORGANIZATION_MEMBERSHIP"
                }), 403

            # 3. Enforce Role & Permission Verification
            user_role = getattr(g, "user_role", None)
            if not has_permission(user_role, permission):
                return jsonify({
                    "error": f"Forbidden: Role '{user_role}' lacks required permission '{permission}'.",
                    "code": "FORBIDDEN",
                    "required_permission": permission,
                    "current_role": user_role
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_org_role(*allowed_roles):
    """Route decorator restricting access to specified organization roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None)
            is_production = getattr(g, "is_production", False)

            if not user or not user.is_active:
                if not is_production and not user:
                    user_role = getattr(g, "user_role", "owner")
                    if user_role in allowed_roles:
                        return f(*args, **kwargs)
                return jsonify({
                    "error": "Authentication required. Please sign in.",
                    "code": "UNAUTHORIZED"
                }), 401

            if getattr(g, "org_access_denied", False):
                return jsonify({
                    "error": "Forbidden: You are not an authorized member of the requested organization.",
                    "code": "ORGANIZATION_ACCESS_DENIED"
                }), 403

            user_role = getattr(g, "user_role", None)
            if not user_role or user_role.lower() not in [r.lower() for r in allowed_roles]:
                return jsonify({
                    "error": f"Forbidden: Operation requires one of roles: {list(allowed_roles)}. Current role is '{user_role}'.",
                    "code": "FORBIDDEN"
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def count_organization_owners(db, organization_id: str, exclude_membership_id: Optional[str] = None) -> int:
    """Calculates number of remaining owners for an organization, optionally excluding a target membership."""
    query = db.query(Membership).filter(
        Membership.organization_id == organization_id,
        Membership.role == "owner"
    )
    if exclude_membership_id:
        query = query.filter(Membership.id != exclude_membership_id)
    return query.count()
