"""Cloudflare Worker entry point for OFFTune Business Desk."""

import hashlib
import html
import hmac
import json
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


def _money(minor):
    return f"{(int(minor or 0) / 100):,.2f}"


def _json_list(value):
    try:
        result = json.loads(value or "[]")
        return result if isinstance(result, list) else []
    except (ValueError, TypeError):
        return []


async def _signed_in_user(request: Request):
    cookie = request.cookies.get("offtune_session")
    if not cookie:
        return None
    return await _env(request).DB.prepare(
        "SELECT u.id,u.name,u.email,u.role,u.manager_id,u.job_title,u.designation_id,u.avatar_data "
        "FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
    ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())).first()


async def _require_user(request: Request, roles=None):
    user = await _signed_in_user(request)
    if not user:
        return None, JSONResponse({"error": "Sign in to continue"}, status_code=401)
    if roles and user["role"] not in roles:
        return None, JSONResponse({"error": "You do not have access to this section"}, status_code=403)
    if request.method not in ("GET", "HEAD"):
        cookie = request.cookies.get("offtune_session")
        session = await _env(request).DB.prepare(
            "SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?"
        ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())).first()
        if not session or not hmac.compare_digest(
            str(request.headers.get("x-csrf-token", "")), str(session["csrf"])
        ):
            return None, JSONResponse({"error": "Refresh the page and try again"}, status_code=403)
    return user, None


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
        "u.designation_id,u.avatar_data,d.name designation,d.permissions_json,d.data_permissions_json "
        "FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN designations d ON d.id=u.designation_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
    ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())).first()
    if not session:
        return {"setup_required": count["n"] == 0, "user": None, "csrf": None,
                "workspace_preview": False, "owner_name": None}
    return {"setup_required": False, "user": {"id": session["id"], "name": session["name"],
            "email": session["email"], "role": session["role"], "manager_id": session["manager_id"],
            "job_title": session["job_title"] or "", "designation_id": session["designation_id"],
            "designation": session["job_title"] or session["designation"] or session["role"].title(),
            "permissions": _json_list(session["permissions_json"]),
            "data_permissions": _json_list(session["data_permissions_json"]),
            "avatar_data": session["avatar_data"] or ""}, "csrf": session["csrf"],
            "workspace_preview": False, "owner_name": None}


@app.get("/api/products")
async def products(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    rows = await _env(request).DB.prepare(
        "SELECT id,sku,name,product_type,price_minor,currency,installment_allowed,commission_rate,active "
        "FROM products WHERE active=1 OR ?='owner' ORDER BY active DESC,name"
    ).bind(user["role"]).all()
    return [{"id": r["id"], "sku": r["sku"], "name": r["name"],
             "product_type": r["product_type"], "price": _money(r["price_minor"]),
             "currency": r["currency"], "installment_allowed": bool(r["installment_allowed"]),
             "active": bool(r["active"]), "price_set": int(r["price_minor"]) > 0,
             **({"commission_rate": r["commission_rate"]} if user["role"] != "employee" else {})}
            for r in rows["results"]]


@app.get("/api/batches")
async def batches(request: Request):
    _, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    rows = await _env(request).DB.prepare(
        "SELECT b.id,b.name,b.product_id,p.name product,b.start_date,b.end_date,b.status "
        "FROM batches b LEFT JOIN products p ON p.id=b.product_id "
        "ORDER BY COALESCE(b.start_date,'9999-12-31') DESC,b.name"
    ).all()
    return rows["results"]


@app.get("/api/orders")
async def orders(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = ""
    binds = []
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds = [user["id"], user["id"]]
    rows = await db.prepare(
        "SELECT o.*,c.name customer_name,c.phone,c.email,u.name employee_name FROM orders o "
        "JOIN customers c ON c.id=o.customer_id LEFT JOIN users u ON u.id=o.employee_id "
        "WHERE o.status!='void'" + scope + " ORDER BY o.order_date DESC,o.id DESC"
    ).bind(*binds).all()
    result = []
    for order in rows["results"]:
        item_rows = await db.prepare(
            "SELECT oi.id order_item_id,p.id product_id,p.name,p.product_type,oi.quantity,oi.unit_price_minor,"
            "oi.discount_minor,oi.line_total_minor,b.id batch_id,b.name batch_name FROM order_items oi "
            "JOIN products p ON p.id=oi.product_id LEFT JOIN batches b ON b.id=oi.batch_id "
            "WHERE oi.order_id=? ORDER BY oi.id"
        ).bind(order["id"]).all()
        receipts = await db.prepare(
            "SELECT COALESCE(SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END),0) n "
            "FROM payments WHERE order_id=?"
        ).bind(order["id"]).first()
        received = int(receipts["n"] or 0)
        total = int(order["total_minor"] or 0)
        items = item_rows["results"]
        weights = [max(0, int(item["line_total_minor"] or 0)) for item in items]
        denominator = sum(weights) or 1
        alloc_total = max(0, total)
        alloc_received = min(alloc_total, max(0, received))
        products_json = []
        for index, item in enumerate(items):
            expected_part = (alloc_total * weights[index]) // denominator
            received_part = (alloc_received * weights[index]) // denominator
            products_json.append({"order_item_id": item["order_item_id"], "id": item["product_id"],
                "name": item["name"], "type": item["product_type"], "batch_id": item["batch_id"],
                "batch": item["batch_name"], "quantity": item["quantity"],
                "unit_price": _money(item["unit_price_minor"]), "discount": _money(item["discount_minor"]),
                "order_value": _money(expected_part), "received": _money(received_part),
                "pending": _money(max(0, expected_part - received_part))})
        base = {"id": order["id"], "customer_id": order["customer_id"], "employee_id": order["employee_id"],
                "can_manage": user["role"] == "owner" or (user["role"] == "manager" and order["employee_id"] == user["id"]) or (user["role"] == "employee" and order["employee_id"] == user["id"]),
                "order_no": order["order_no"], "date": order["order_date"],
                "course_start_date": order["course_start_date"], "enrollment_status": order["enrollment_status"],
                "customer": order["customer_name"], "employee": order["employee_name"] or "Unassigned",
                "products": products_json}
        if user["role"] in ("owner", "employee"):
            base.update({"total": _money(total), "received": _money(received),
                "pending": _money(max(0, total - received)), "currency": order["currency"],
                "discount": _money(order["discount_minor"]), "discount_label": order["discount_label"]})
        else:
            base["pending"] = _money(max(0, total - received))
        result.append(base)
    return result


@app.get("/api/team")
async def team(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    db = _env(request).DB
    if user["role"] == "owner":
        rows = await db.prepare(
            "SELECT u.id,u.name,u.email,u.role,u.job_title,u.designation_id,u.avatar_data,u.manager_id,u.is_active,"
            "d.name designation,d.permissions_json,d.data_permissions_json,m.name manager_name FROM users u "
            "LEFT JOIN designations d ON d.id=u.designation_id LEFT JOIN users m ON m.id=u.manager_id "
            "WHERE u.role!='owner' ORDER BY u.manager_id,u.name"
        ).all()
    else:
        rows = await db.prepare(
            "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 "
            "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) "
            "SELECT u.id,u.name,u.email,u.role,u.job_title,u.designation_id,u.avatar_data,u.manager_id,u.is_active,"
            "d.name designation,d.permissions_json,d.data_permissions_json,m.name manager_name FROM users u "
            "LEFT JOIN designations d ON d.id=u.designation_id LEFT JOIN users m ON m.id=u.manager_id "
            "WHERE u.id IN (SELECT id FROM team) ORDER BY u.role,u.name"
        ).bind(user["id"]).all()
    result = []
    for row in rows["results"]:
        result.append({"id": row["id"], "name": row["name"], "email": row["email"],
            "role": row["role"], "job_title": row["job_title"] or "", "designation_id": row["designation_id"],
            "designation": row["job_title"] or row["designation"] or row["role"].title(),
            "permissions": _json_list(row["permissions_json"]),
            "data_permissions": _json_list(row["data_permissions_json"]),
            "avatar_data": row["avatar_data"] or "", "manager_id": row["manager_id"],
            "manager_name": row["manager_name"], "active": bool(row["is_active"])})
    return result


@app.get("/api/team/messages")
async def team_messages(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    rows = await _env(request).DB.prepare(
        "SELECT m.*,s.name sender_name,s.role sender_role,r.name recipient_name FROM team_messages m "
        "JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id "
        "WHERE m.recipient_id=? OR m.sender_id=? ORDER BY COALESCE(m.remind_at,m.created_at) DESC,m.id DESC LIMIT 200"
    ).bind(user["id"], user["id"]).all()
    return [{"id": r["id"], "title": r["title"], "body": r["body"], "sender_id": r["sender_id"],
        "sender": r["sender_name"], "sender_role": r["sender_role"], "recipient_id": r["recipient_id"],
        "recipient": r["recipient_name"], "remind_at": r["remind_at"], "read": bool(r["read_at"]),
        "completed": bool(r["completed_at"]), "created_at": r["created_at"],
        "direction": "inbox" if r["recipient_id"] == user["id"] else "sent"} for r in rows["results"]]


@app.get("/api/settings")
async def settings(request: Request):
    _, error = await _require_user(request, ("owner",))
    if error:
        return error
    rows = await _env(request).DB.prepare("SELECT key,value FROM settings").all()
    return {r["key"]: r["value"] for r in rows["results"]}


@app.get("/api/dashboard")
async def dashboard(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    if user["role"] != "owner":
        own = await db.prepare(
            "SELECT COALESCE((SELECT SUM(e.amount_minor-e.paid_minor) FROM commission_events e WHERE e.employee_id=?),0) incentive_pending,"
            "COALESCE((SELECT SUM(e.paid_minor) FROM commission_events e WHERE e.employee_id=?),0) incentive_paid,"
            "(SELECT COUNT(*) FROM orders WHERE employee_id=? AND status='active') conversions"
        ).bind(user["id"], user["id"], user["id"]).first()
        if user["role"] == "employee":
            return {"role": "employee", "incentive_pending": _money(max(0, own["incentive_pending"])),
                    "incentive_recovery": _money(max(0, -own["incentive_pending"])),
                    "incentive_paid": _money(own["incentive_paid"]), "targets": {"weekly": {}, "monthly": {}}, "team": []}
        return {"role": "manager", "team": [], "conversions": own["conversions"],
                "outstanding": _money(0), "students_to_collect": 0,
                "incentive_due": _money(max(0, own["incentive_pending"])),
                "incentive_paid": _money(own["incentive_paid"]),
                "incentive_recovery": _money(max(0, -own["incentive_pending"])),
                "my_incentive_due": _money(max(0, own["incentive_pending"])),
                "my_incentive_paid": _money(own["incentive_paid"]),
                "targets": {"weekly": {}, "monthly": {}, "assigned_by": None}}
    totals = await db.prepare(
        "SELECT COALESCE((SELECT SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END) FROM payments),0) received,"
        "COALESCE((SELECT SUM(total_minor) FROM orders WHERE status='active'),0) expected,"
        "COALESCE((SELECT SUM(amount_minor) FROM expenses),0) expenses,"
        "(SELECT COUNT(*) FROM orders WHERE status='active') conversions,"
        "COALESCE((SELECT SUM(amount_minor-paid_minor) FROM commission_events),0) incentive_pending,"
        "COALESCE((SELECT SUM(paid_minor) FROM commission_events),0) incentive_paid"
    ).first()
    team = await db.prepare(
        "SELECT u.id,u.name,u.role,COUNT(DISTINCT o.id) conversions,"
        "COALESCE((SELECT SUM(total_minor) FROM orders ox WHERE ox.employee_id=u.id AND ox.status='active'),0) expected,"
        "COALESCE((SELECT conversion_target FROM targets t WHERE t.user_id=u.id AND t.period=strftime('%Y-%m','now') AND t.period_type='monthly'),0) target,"
        "COALESCE(SUM(CASE WHEN p.payment_type='receipt' THEN p.amount_minor ELSE -p.amount_minor END),0) received,"
        "COALESCE((SELECT SUM(e.amount_minor-e.paid_minor) FROM commission_events e WHERE e.employee_id=u.id),0) incentive_pending,"
        "COALESCE((SELECT SUM(e.paid_minor) FROM commission_events e WHERE e.employee_id=u.id),0) incentive_paid "
        "FROM users u LEFT JOIN orders o ON o.employee_id=u.id AND o.status='active' "
        "LEFT JOIN payments p ON p.order_id=o.id WHERE u.role IN ('manager','employee') AND u.is_active=1 "
        "GROUP BY u.id ORDER BY u.name"
    ).all()
    received = int(totals["received"] or 0)
    expected = int(totals["expected"] or 0)
    expenses = int(totals["expenses"] or 0)
    pending = max(0, expected - received)
    people = []
    for row in team["results"]:
        people.append({"id": row["id"], "name": row["name"], "role": row["role"],
                       "conversions": row["conversions"], "target": row["target"],
                       "received": _money(row["received"]),
                       "pending": _money(max(0, int(row["expected"] or 0) - int(row["received"] or 0))),
                       "incentive_pending": _money(max(0, int(row["incentive_pending"] or 0))),
                       "incentive_recovery": _money(max(0, -int(row["incentive_pending"] or 0))),
                       "incentive_paid": _money(row["incentive_paid"])})
    return {"role": "owner", "received": _money(received), "pending": _money(pending),
            "expected": _money(expected), "expenses": _money(expenses),
            "net_cash": _money(received - expenses),
            "collection_rate": round(received / expected * 100, 1) if expected else 0,
            "conversions": totals["conversions"],
            "incentive_pending": _money(max(0, int(totals["incentive_pending"] or 0))),
            "incentive_recovery": _money(max(0, -int(totals["incentive_pending"] or 0))),
            "incentive_paid": _money(totals["incentive_paid"]), "team": people}


@app.get("/api/invoices")
async def invoices(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = ""
    binds = []
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds = [user["id"], user["id"]]
    rows = await db.prepare(
        "SELECT i.id,i.order_id,i.invoice_no,i.issued_on,i.status,i.invoice_kind,i.installment_id,"
        "inst.installment_no,inst.due_date,COALESCE(ip.installment_received_minor,0) installment_received_minor,"
        "o.customer_id,COALESCE(ip.order_no,o.order_no) order_no,COALESCE(ip.currency,o.currency) currency,"
        "COALESCE(ip.customer_name,c.name) customer,COALESCE(ip.total_minor,o.total_minor) total_minor,"
        "CASE WHEN i.installment_id IS NOT NULL THEN COALESCE((SELECT SUM(pa.amount_minor) FROM payment_allocations pa WHERE pa.installment_id=i.installment_id),0) "
        "ELSE COALESCE((SELECT SUM(CASE WHEN p.payment_type='receipt' THEN p.amount_minor ELSE -p.amount_minor END) FROM payments p WHERE p.order_id=i.order_id),0) END received_minor,"
        "COALESCE((SELECT group_concat(DISTINCT ii.product_type) FROM invoice_items ii WHERE ii.invoice_id=i.id),(SELECT group_concat(DISTINCT p.product_type) FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=i.order_id)) product_types,"
        "COALESCE((SELECT group_concat(ii.description,' · ') FROM invoice_items ii WHERE ii.invoice_id=i.id),(SELECT group_concat(p.name,' · ') FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=i.order_id)) item_names "
        "FROM invoices i JOIN orders o ON o.id=i.order_id JOIN customers c ON c.id=o.customer_id LEFT JOIN installments inst ON inst.id=i.installment_id LEFT JOIN invoice_profiles ip ON ip.invoice_id=i.id WHERE 1=1" + scope + " ORDER BY i.issued_on DESC,i.id DESC"
    ).bind(*binds).all()
    result = []
    for r in rows["results"]:
        total = max(0, int(r["total_minor"] or 0))
        raw = int(r["received_minor"] or 0)
        if r["installment_id"]:
            raw = max(0, raw - int(r["installment_received_minor"] or 0))
        received = max(0, min(total, raw))
        types = set((r["product_types"] or "").split(","))
        kind = "mixed" if "course" in types and ("sample_pack" in types or "digital_product" in types) else "course" if "course" in types else "product"
        no = r["installment_no"]
        label = "Booking" if no == -1 else "Admission" if no == 0 else f"EMI {no}" if no is not None else ""
        result.append({"id": r["id"], "order_id": r["order_id"], "customer_id": r["customer_id"],
                       "invoice_no": r["invoice_no"], "issued_on": r["issued_on"], "order_no": r["order_no"],
                       "customer": r["customer"], "items": r["item_names"] or "—", "kind": kind,
                       "invoice_kind": r["invoice_kind"] or "order", "installment_id": r["installment_id"],
                       "installment_no": no, "installment_label": label, "due_date": r["due_date"],
                       "status": r["status"], "currency": r["currency"], "total": _money(total),
                       "received": _money(received), "balance": _money(max(0, total - received))})
    return result


async def _invoice_detail(request: Request, invoice_id: int):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return None, error
    db = _env(request).DB
    scope = ""
    binds = [invoice_id]
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds.extend([user["id"], user["id"]])
    row = await db.prepare(
        "SELECT i.id,i.order_id,i.invoice_no,i.issued_on,i.status,i.invoice_kind,i.installment_id,"
        "o.order_no,o.order_date,o.currency,o.subtotal_minor,o.discount_minor,o.tax_minor,o.total_minor,"
        "c.name customer,c.phone,c.email,ip.business_name,ip.business_email,ip.business_phone,ip.business_website,"
        "ip.business_address,ip.business_tax_id,ip.logo_data,ip.customer_name,ip.customer_phone,ip.customer_email,"
        "ip.currency snap_currency,ip.order_no snap_order_no,ip.order_date snap_order_date,ip.subtotal_minor snap_subtotal_minor,"
        "ip.discount_minor snap_discount_minor,ip.tax_minor snap_tax_minor,ip.total_minor snap_total_minor,"
        "ip.installment_received_minor FROM invoices i JOIN orders o ON o.id=i.order_id "
        "JOIN customers c ON c.id=o.customer_id LEFT JOIN invoice_profiles ip ON ip.invoice_id=i.id "
        "WHERE i.id=?" + scope
    ).bind(*binds).first()
    if not row:
        return None, JSONResponse({"error": "Invoice not found"}, status_code=404)
    received_row = await db.prepare(
        "SELECT COALESCE(SUM(amount_minor),0) n FROM payment_allocations WHERE installment_id=?"
    ).bind(row["installment_id"]).first() if row["installment_id"] else await db.prepare(
        "SELECT COALESCE(SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END),0) n FROM payments WHERE order_id=?"
    ).bind(row["order_id"]).first()
    received = int(received_row["n"] or 0)
    if row["installment_id"]:
        received = max(0, received - int(row["installment_received_minor"] or 0))
    has_snapshot = bool(row["business_name"])
    if has_snapshot:
        items_rows = await db.prepare(
            "SELECT product_type,sku,description name,batch_name,quantity,unit_price_minor,discount_minor,line_total_minor "
            "FROM invoice_items WHERE invoice_id=? ORDER BY id"
        ).bind(invoice_id).all()
    else:
        items_rows = await db.prepare(
            "SELECT p.product_type,p.sku,p.name,COALESCE(b.name,'') batch_name,oi.quantity,oi.unit_price_minor,oi.discount_minor,oi.line_total_minor "
            "FROM order_items oi JOIN products p ON p.id=oi.product_id LEFT JOIN batches b ON b.id=oi.batch_id "
            "WHERE oi.order_id=? ORDER BY oi.id"
        ).bind(row["order_id"]).all()
    total = int((row["snap_total_minor"] if has_snapshot else row["total_minor"]) or 0)
    subtotal = int((row["snap_subtotal_minor"] if has_snapshot else row["subtotal_minor"]) or 0)
    discount = int((row["snap_discount_minor"] if has_snapshot else row["discount_minor"]) or 0)
    tax = int((row["snap_tax_minor"] if has_snapshot else row["tax_minor"]) or 0)
    inst = await db.prepare("SELECT installment_no,due_date FROM installments WHERE id=?").bind(row["installment_id"]).first() if row["installment_id"] else None
    sched_rows = await db.prepare(
        "SELECT i.installment_no,i.due_date,i.amount_minor,COALESCE(SUM(pa.amount_minor),0) received_minor "
        "FROM installments i LEFT JOIN payment_allocations pa ON pa.installment_id=i.id "
        "WHERE i.order_id=? GROUP BY i.id ORDER BY i.installment_no"
    ).bind(row["order_id"]).all()
    schedule = [{"installment_no": r["installment_no"], "due_date": r["due_date"],
        "amount": _money(r["amount_minor"]), "received": _money(r["received_minor"]),
        "balance": _money(max(0, int(r["amount_minor"] or 0) - int(r["received_minor"] or 0))),
        "status": "Paid" if int(r["amount_minor"] or 0) <= int(r["received_minor"] or 0) else "Part paid" if r["received_minor"] else "Unpaid"}
        for r in sched_rows["results"]]
    if inst:
        schedule = [r for r in schedule if r["installment_no"] == inst["installment_no"]]
        for entry in schedule:
            entry.update({"amount": _money(total), "received": _money(min(total, max(0, received))),
                          "balance": _money(max(0, total - received)),
                          "status": "Paid" if total <= received else "Part paid" if received else "Unpaid"})
    settings_rows = await db.prepare("SELECT key,value FROM settings WHERE key IN ('business_name','business_email','business_phone','business_website','business_address','business_tax_id','invoice_logo_data')").all()
    cfg = {r["key"]: r["value"] for r in settings_rows["results"]}
    money_total = max(0, total)
    payload = {"invoice_no": row["invoice_no"], "issued_on": row["issued_on"],
        "invoice_kind": row["invoice_kind"] or "order", "status": row["status"],
        "installment_no": inst["installment_no"] if inst else None,
        "due_date": inst["due_date"] if inst else "", "document_title": "Installment invoice" if inst else "Invoice",
        "order_no": row["snap_order_no"] if has_snapshot else row["order_no"],
        "order_date": row["snap_order_date"] if has_snapshot else row["order_date"],
        "business_name": row["business_name"] if has_snapshot else cfg.get("business_name", "OFFTune Business Desk"),
        "business_email": row["business_email"] if has_snapshot else cfg.get("business_email", ""),
        "business_phone": row["business_phone"] if has_snapshot else cfg.get("business_phone", ""),
        "business_website": row["business_website"] if has_snapshot else cfg.get("business_website", ""),
        "business_address": row["business_address"] if has_snapshot else cfg.get("business_address", ""),
        "business_tax_id": row["business_tax_id"] if has_snapshot else cfg.get("business_tax_id", ""),
        "invoice_logo_data": row["logo_data"] if has_snapshot else cfg.get("invoice_logo_data", ""),
        "currency": row["snap_currency"] if has_snapshot else row["currency"],
        "customer": {"name": row["customer_name"] if has_snapshot else row["customer"],
            "phone": row["customer_phone"] if has_snapshot else row["phone"],
            "email": row["customer_email"] if has_snapshot else row["email"]},
        "items": [{"product_type": x["product_type"], "sku": x["sku"], "name": x["name"],
            "batch": x["batch_name"], "quantity": x["quantity"], "unit_price": _money(x["unit_price_minor"]),
            "discount": _money(x["discount_minor"]), "line_total": _money(x["line_total_minor"])} for x in items_rows["results"]],
        "payment_schedule": schedule, "subtotal": _money(subtotal), "discount": _money(discount),
        "tax": _money(tax), "total": _money(money_total), "received": _money(min(money_total, max(0, received))),
        "balance": _money(max(0, money_total - received)), "template": {"style": "studio", "accent_color": "#e51b2b"}}
    return payload, None


def _invoice_html(data):
    esc = lambda value: html.escape(str(value or ""), quote=True)
    lines = "".join(f"<tr><td><b>{esc(item['name'])}</b><small>{esc(item.get('batch') or item.get('sku') or '')}</small></td><td>{esc(item['quantity'])}</td><td>{esc(item['unit_price'])}</td><td>{esc(item['discount'])}</td><td><b>{esc(item['line_total'])}</b></td></tr>" for item in data["items"])
    logo = f"<img class='logo' src='{esc(data['invoice_logo_data'])}' alt='OFFTune logo'>" if data.get("invoice_logo_data", "").startswith("data:image/") else ""
    website = f"<a href='{esc(data['business_website'])}'>{esc(data['business_website'])}</a>" if data.get("business_website", "").startswith(("https://", "http://")) else ""
    status = "PAID" if float(data["balance"].replace(",", "")) == 0 else "BALANCE DUE"
    return "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><meta charset='utf-8'><title>" + esc(data["invoice_no"]) + "</title><style>body{margin:0;background:#f3f5f9;color:#182033;font:15px Arial,sans-serif}.sheet{max-width:760px;margin:24px auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 18px 60px #17253d18}.bar{height:8px;background:#e51b2b}.pad{padding:34px}.top,.meta,.summary{display:flex;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:12px}.logo{width:48px;height:48px;object-fit:contain}.muted,small{display:block;color:#788195;margin-top:6px}.number{text-align:right}.number h1{font-size:29px;margin:0}.pill{display:inline-block;margin-top:10px;padding:8px 12px;border-radius:30px;background:#fff0f0;color:#bd1725;font-size:11px;font-weight:bold;letter-spacing:.08em}.meta{margin:34px 0;padding:20px;background:#f7f8fb;border-radius:12px}.meta b{display:block;margin-top:7px}.meta label{color:#788195;font-size:10px;letter-spacing:.12em;font-weight:bold}table{width:100%;border-collapse:collapse}th{text-align:left;color:#788195;font-size:10px;letter-spacing:.08em;padding:12px 8px;border-bottom:1px solid #e9ecf2}td{padding:15px 8px;border-bottom:1px solid #edf0f4;font-size:13px}td:first-child{width:42%}.summary{margin-top:26px}.totals{width:260px;margin-left:auto}.totals div{display:flex;justify-content:space-between;padding:7px 0;color:#687286}.totals .grand{border-top:1px solid #e2e6ee;padding-top:14px;color:#182033;font-size:17px;font-weight:bold}.balance{margin-top:16px;padding:18px;border-radius:12px;background:#fff7e9;display:flex;justify-content:space-between;color:#8a5600;font-weight:bold}.foot{margin-top:30px;padding-top:18px;border-top:1px solid #edf0f4;color:#788195;font-size:12px}@media(max-width:600px){.sheet{margin:0;border-radius:0}.pad{padding:22px 16px}.top{align-items:flex-start}.number h1{font-size:21px}.meta{padding:14px;gap:10px}.meta label{font-size:9px}table{font-size:11px}th,td{padding:10px 4px}td:first-child{width:38%}.totals{width:100%}.summary{display:block}.total-label{font-size:12px}}</style></head><body><main class='sheet'><div class='bar'></div><div class='pad'><header class='top'><div class='brand'>"+logo+"<div><b>"+esc(data["business_name"])+"</b><small>"+esc(data.get("business_email"))+"</small><small>"+esc(data.get("business_phone"))+" · "+website+"</small></div></div><div class='number'><h1>INVOICE</h1><b>"+esc(data["invoice_no"])+"</b><span class='pill'>"+status+"</span></div></header><section class='meta'><div><label>BILL TO</label><b>"+esc(data["customer"].get("name"))+"</b><small>"+esc(data["customer"].get("email"))+"</small><small>"+esc(data["customer"].get("phone"))+"</small></div><div><label>ISSUED</label><b>"+esc(data["issued_on"])+"</b><small>Order "+esc(data["order_no"])+"</small></div><div><label>PAYMENT DUE</label><b>"+esc(data.get("due_date") or "As scheduled")+"</b></div></section><table><thead><tr><th>DESCRIPTION</th><th>QTY</th><th>PRICE</th><th>DISCOUNT</th><th>AMOUNT</th></tr></thead><tbody>"+lines+"</tbody></table><section class='summary'><div></div><div class='totals'><div><span>Subtotal</span><b>"+esc(data["subtotal"])+"</b></div><div><span>Discount</span><b>− "+esc(data["discount"])+"</b></div><div><span>Tax</span><b>"+esc(data["tax"])+"</b></div><div class='grand'><span>Total</span><b>"+esc(data["total"])+"</b></div><div><span>Received</span><b>"+esc(data["received"])+"</b></div><div class='balance'><span>Balance due</span><span>"+esc(data["balance"])+"</span></div></div></section><footer class='foot'>Thank you for choosing "+esc(data["business_name"])+". Please contact us if you need help with this invoice.<br>"+website+"</footer></div></main></body></html>"


@app.get("/api/invoices/{invoice_id}/preview")
async def invoice_preview(invoice_id: int, request: Request):
    detail, error = await _invoice_detail(request, invoice_id)
    if error:
        return error
    recipient = detail["customer"].get("email") or ""
    masked = (recipient[:1] + "•••@" + recipient.split("@", 1)[1]) if "@" in recipient else ""
    return {"html": _invoice_html(detail), "invoice_no": detail["invoice_no"],
        "recipient_hint": masked, "can_send": False,
        "send_block_reason": "Hosted email delivery has not been connected yet.",
        "pay_link_expected": float(detail["balance"].replace(",", "")) > 0}


@app.get("/api/invoices/{invoice_id}")
async def invoice_detail(request: Request, invoice_id: int):
    detail, error = await _invoice_detail(request, invoice_id)
    return error if error else detail


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
        digest = hashlib.sha256(cookie.encode()).hexdigest()
        session = await _env(request).DB.prepare(
            "SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?"
        ).bind(digest, int(time.time())).first()
        if session and not hmac.compare_digest(
            str(request.headers.get("x-csrf-token", "")), str(session["csrf"])
        ):
            return JSONResponse({"error": "Refresh the page and try again"}, status_code=403)
        if session:
            await _env(request).DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(digest).run()
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
