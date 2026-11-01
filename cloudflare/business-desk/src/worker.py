"""Cloudflare Worker entry point for OFFTune Business Desk.

The first ported slice covers owner setup and authentication. Other business
API routes remain unavailable until they have been ported and reviewed.
"""

import hashlib
import hmac
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from workers import asgi


app = FastAPI()
SESSION_TTL = 60 * 60 * 12
PBKDF2_ROUNDS = 310_000


def _env(request: Request):
    return request.scope["env"]


def _hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Use a password with at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def _password_matches(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_hex, expected = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


async def _new_session(request: Request, user_id: int):
    db = _env(request).DB
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    await db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(int(time.time())).run()
    await db.prepare("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)").bind(
        hashlib.sha256(token.encode()).hexdigest(), user_id, csrf, int(time.time()) + SESSION_TTL
    ).run()
    return token, csrf


def _set_cookie(response: Response, token: str):
    response.set_cookie("offtune_session", token, max_age=SESSION_TTL, httponly=True,
                        secure=True, samesite="strict", path="/")


@app.get("/healthz")
async def health(request: Request):
    try:
        result = await _env(request).DB.prepare(
            "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).first()
        return {"status": "ready", "schema_tables": result["count"]}
    except Exception:
        return JSONResponse({"status": "database_unavailable"}, status_code=503)


@app.get("/api/auth/session")
async def auth_session(request: Request):
    db = _env(request).DB
    count = await db.prepare("SELECT COUNT(*) AS n FROM users").first()
    cookie = request.cookies.get("offtune_session")
    if not cookie:
        return {"setup_required": count["n"] == 0, "user": None, "csrf": None,
                "workspace_preview": False, "owner_name": None}
    session = await db.prepare(
        "SELECT s.csrf,s.expires_at,u.id,u.name,u.email,u.role,u.manager_id,u.job_title,"
        "u.designation_id,u.avatar_data FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
    ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())).first()
    if not session:
        return {"setup_required": count["n"] == 0, "user": None, "csrf": None,
                "workspace_preview": False, "owner_name": None}
    return {"setup_required": False, "user": {"id": session["id"], "name": session["name"],
            "email": session["email"], "role": session["role"], "manager_id": session["manager_id"],
            "job_title": session["job_title"] or "", "designation_id": session["designation_id"],
            "designation": "Owner", "permissions": [], "data_permissions": [],
            "avatar_data": session["avatar_data"] or ""}, "csrf": session["csrf"],
            "workspace_preview": False, "owner_name": None}


@app.post("/api/auth/setup")
async def auth_setup(request: Request):
    data = await request.json()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    if not name or len(name) > 120 or "@" not in email or len(email) > 254:
        return JSONResponse({"error": "Enter a valid owner name and email"}, status_code=400)
    db = _env(request).DB
    count = await db.prepare("SELECT COUNT(*) AS n FROM users").first()
    if count["n"]:
        return JSONResponse({"error": "Workspace setup is already complete"}, status_code=409)
    try:
        password = _hash_password(str(data.get("password", "")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    result = await db.prepare(
        "INSERT INTO users(name,email,password_hash,role) "
        "SELECT ?,?,?,'owner' WHERE NOT EXISTS (SELECT 1 FROM users)"
    ).bind(name, email, password).run()
    user_id = result["meta"]["last_row_id"]
    if not user_id:
        return JSONResponse({"error": "Workspace setup is already complete"}, status_code=409)
    token, csrf = await _new_session(request, user_id)
    response = JSONResponse({"ok": True, "csrf": csrf})
    _set_cookie(response, token)
    return response


@app.post("/api/auth/login")
async def auth_login(request: Request):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()
    db = _env(request).DB
    user = await db.prepare("SELECT id,password_hash,is_active FROM users WHERE lower(email)=?").bind(email).first()
    if not user or not user["is_active"] or not _password_matches(str(data.get("password", "")), user["password_hash"]):
        return JSONResponse({"error": "Email or password is incorrect"}, status_code=401)
    token, csrf = await _new_session(request, user["id"])
    response = JSONResponse({"ok": True, "csrf": csrf})
    _set_cookie(response, token)
    return response


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    cookie = request.cookies.get("offtune_session")
    if cookie:
        await _env(request).DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(
            hashlib.sha256(cookie.encode()).hexdigest()
        ).run()
    response = JSONResponse({"ok": True})
    response.delete_cookie("offtune_session", path="/", secure=True, httponly=True, samesite="strict")
    return response


@app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
async def frontend(path: str, request: Request):
    if path.startswith("api/"):
        return JSONResponse({"error": "This business API route is not ported yet."}, status_code=503)
    if request.method not in ("GET", "HEAD"):
        return JSONResponse({"error": "Method not allowed"}, status_code=405)
    asset_path = path or "index.html"
    upstream = await _env(request).ASSETS.fetch(f"https://assets.local/{asset_path}")
    body = await upstream.bytes()
    return Response(content=body, status_code=upstream.status, headers=dict(upstream.headers))


Default = asgi.entrypoint(app)
