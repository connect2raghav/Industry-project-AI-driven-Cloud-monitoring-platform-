"""
JWT Authentication & Role-Based Access Control Engine — SQLite backed
"""
import jwt
import hashlib
import uuid
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List
from engines.db import get_conn, init_db

JWT_SECRET = os.environ.get("JWT_SECRET", "ram-antivirus-cloud-security-super-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

def _hash_password(password: str) -> str:
    salt = "ram-av-salt"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def _row_to_user(row) -> Dict:
    if row is None:
        return None
    return {
        "user_id": row["user_id"], "username": row["username"], "email": row["email"],
        "password_hash": row["password_hash"], "role": row["role"], "full_name": row["full_name"],
        "created_at": row["created_at"], "last_login": row["last_login"],
        "is_active": bool(row["is_active"])
    }

def _get_user(username: str) -> Optional[Dict]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return _row_to_user(row)

def _save_user(user: Dict):
    conn = get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO users
           (user_id,username,email,password_hash,role,full_name,created_at,last_login,is_active)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (user["user_id"], user["username"], user["email"], user["password_hash"],
         user["role"], user["full_name"], user["created_at"], user["last_login"], int(user["is_active"]))
    )
    conn.commit()
    conn.close()

# Seed default users if not present
def _seed_defaults():
    _defaults = [
        {"username": "admin",    "password": "admin123",   "email": "admin@ramantivirus.com",   "role": "admin",   "full_name": "System Administrator"},
        {"username": "analyst1", "password": "analyst123", "email": "analyst@ramantivirus.com", "role": "analyst", "full_name": "Security Analyst"},
        {"username": "viewer1",  "password": "viewer123",  "email": "viewer@ramantivirus.com",  "role": "viewer",  "full_name": "Dashboard Viewer"},
    ]
    for u in _defaults:
        if not _get_user(u["username"]):
            _save_user({
                "user_id": str(uuid.uuid4()), "username": u["username"], "email": u["email"],
                "password_hash": _hash_password(u["password"]), "role": u["role"],
                "full_name": u["full_name"], "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_login": None, "is_active": True
            })

_seed_defaults()


# ── Role Permissions ─────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": {
        "description": "Full access — all endpoints, remediation, user management",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read", "remediation:execute",
            "compliance:read", "compliance:generate", "compliance:export",
            "simulation:read", "simulation:execute",
            "users:read", "users:manage",
            "risk:read", "risk:configure"
        ]
    },
    "analyst": {
        "description": "View + alerts + compliance + ML analysis",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "ml:execute", "remediation:read",
            "compliance:read", "compliance:generate",
            "simulation:read", "simulation:execute",
            "risk:read"
        ]
    },
    "viewer": {
        "description": "Read-only dashboard access",
        "permissions": [
            "dashboard:read", "events:read", "cspm:read", "ciem:read",
            "ml:read", "compliance:read", "risk:read"
        ]
    }
}


# ── Registration ─────────────────────────────────────────────────────────────
def register_user(username: str, password: str, email: str, role: str = "viewer", full_name: str = "") -> Dict:
    """
    Register a new user with the given credentials and role.
    Returns user info (without password hash) or error.
    """
    # Validation
    if not username or len(username) < 3:
        return {"success": False, "error": "Username must be at least 3 characters"}
    
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}
    
    if _get_user(username):
        return {"success": False, "error": f"Username '{username}' already exists"}

    if role not in ROLE_PERMISSIONS:
        return {"success": False, "error": f"Invalid role '{role}'. Must be: admin, analyst, or viewer"}

    conn = get_conn()
    existing_email = conn.execute("SELECT username FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if existing_email:
        return {"success": False, "error": f"Email '{email}' already registered"}

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _save_user({
        "user_id": user_id, "username": username, "email": email,
        "password_hash": _hash_password(password), "role": role,
        "full_name": full_name or username, "created_at": now,
        "last_login": None, "is_active": True
    })
    
    return {
        "success": True,
        "user": {
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name or username,
            "permissions": ROLE_PERMISSIONS[role]["permissions"],
            "created_at": now
        }
    }


# ── Login & Token Generation ─────────────────────────────────────────────────
def login_user(username: str, password: str) -> Dict:
    """
    Authenticate user and return a JWT token.
    """
    user = _get_user(username)

    if not user:
        return {"success": False, "error": "Invalid username or password"}

    if not user["is_active"]:
        return {"success": False, "error": "Account is deactivated. Contact administrator."}

    if user["password_hash"] != _hash_password(password):
        return {"success": False, "error": "Invalid username or password"}

    now = datetime.now(timezone.utc)
    user["last_login"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    _save_user(user)
    
    # Generate JWT token
    payload = {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"],
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iss": "ram-antivirus-cloud-security"
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "success": True,
        "token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"],
            "permissions": ROLE_PERMISSIONS[user["role"]]["permissions"]
        }
    }


# ── Token Verification ───────────────────────────────────────────────────────
def verify_token(token: str) -> Dict:
    """
    Verify and decode a JWT token.
    Returns the decoded payload or error.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"valid": True, "payload": payload}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token has expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": f"Invalid token: {str(e)}"}


def check_permission(token: str, required_permission: str) -> Dict:
    """
    Verify token and check if the user has the required permission.
    """
    result = verify_token(token)
    
    if not result["valid"]:
        return {"authorized": False, "error": result["error"]}
    
    user_permissions = result["payload"].get("permissions", [])
    
    if required_permission in user_permissions:
        return {
            "authorized": True,
            "user": {
                "user_id": result["payload"]["user_id"],
                "username": result["payload"]["username"],
                "role": result["payload"]["role"]
            }
        }
    
    return {
        "authorized": False,
        "error": f"Insufficient permissions. Required: '{required_permission}'. Your role: '{result['payload']['role']}'"
    }


# ── User Management ──────────────────────────────────────────────────────────
def get_all_users() -> List[Dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return [
        {"user_id": r["user_id"], "username": r["username"], "email": r["email"],
         "role": r["role"], "full_name": r["full_name"], "created_at": r["created_at"],
         "last_login": r["last_login"], "is_active": bool(r["is_active"])}
        for r in rows
    ]


def deactivate_user(username: str) -> Dict:
    user = _get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}
    user["is_active"] = False
    _save_user(user)
    return {"success": True, "message": f"User '{username}' deactivated"}


def reactivate_user(username: str) -> Dict:
    user = _get_user(username)
    if not user:
        return {"success": False, "error": f"User '{username}' not found"}
    user["is_active"] = True
    _save_user(user)
    return {"success": True, "message": f"User '{username}' reactivated"}


def get_role_info() -> Dict:
    """Return all role definitions and their permissions."""
    return ROLE_PERMISSIONS


if __name__ == "__main__":
    import json
    
    print("=== Register User ===")
    reg = register_user("testuser", "test123456", "test@example.com", "analyst", "Test User")
    print(json.dumps(reg, indent=2))
    
    print("\n=== Login ===")
    login = login_user("admin", "admin123")
    print(json.dumps(login, indent=2))
    
    print("\n=== Verify Token ===")
    if login["success"]:
        verify = verify_token(login["token"])
        print(json.dumps(verify, indent=2, default=str))
    
    print("\n=== Check Permission ===")
    if login["success"]:
        perm = check_permission(login["token"], "remediation:execute")
        print(json.dumps(perm, indent=2))
