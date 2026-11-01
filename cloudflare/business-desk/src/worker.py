Warning: truncated output (original token count: 52963)
Total output lines: 3230

"""Cloudflare Worker entry point for OFFTune Business Desk."""

import hashlib
import base64
import binascii
import html
import hmac
import json
import secrets
import time
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from workers import asgi


app = FastAPI()
SESSION_TTL = 60 * 60 * 12
PBKDF2_ROUNDS = 310_000
BUSINESS_SETTING_DEFAULTS = {
    "business_name": "OFFTune", "business_email": "", "business_phone": "", "business_website": "",
    "business_address": "", "business_tax_id": "", "currency": "INR", "invoice_prefix": "OFT",
    "invoice_template_style": "studio", "invoice_accent_color": "#e51b2b", "invoice_location": "",
    "invoice_footer_text": "Thank you for choosing OFFTune Business Desk.", "invoice_show_phone": "1",
    "invoice_show_email": "1", "invoice_show_website": "1", "invoice_show_tax_id": "0",
    "invoice_auto_installment_enabled": "1", "invoice_auto_lead_days": "5",
    "expense_categories": "Ads & Marketing,Software & Tools,Salary,Equipment,Utilities,Office Expense,Miscellaneous",
    "payment_methods": "Cash,UPI,Bank Transfer,Cheque,Card,Other", "followup_reminder_lead_days": "5",
}
REMINDER_STAGE_DEFAULTS = [
    {"offset_days": -5, "label": "5 days before", "subject": "Upcoming payment · {order_no}", "body": "Hello {student}, your installment of {amount_due} is due on {due_date}. Please plan your payment."},
    {"offset_days": -1, "label": "1 day before", "subject": "Payment due tomorrow · {order_no}", "body": "Hello {student}, your installment of {amount_due} is due tomorrow ({due_date}). Please make the payment on time."},
    {"offset_days": 0, "label": "Due today", "subject": "Payment due today · {order_no}", "body": "Hello {student}, your installment of {amount_due} is due today ({due_date}). Please pay today or contact our team if you need help."},
    {"offset_days": 3, "label": "3 days overdue", "subject": "Missed installment · {order_no}", "body": "Hello {student}, we have not recorded your installment payment of {amount_due}, due {due_date}. Please pay now."},
    {"offset_days": 5, "label": "5 days overdue", "subject": "Payment follow-up · {order_no}", "body": "Hello {student}, your installment remains unpaid. Please arrange payment or contact our team."},
]
REMINDER_INSTALLMENT_TYPES = ("booking", "admission", "emi", "balance")
ACCESS_FEATURES = {
    "overview": "Overview", "targets": "Targets", "collections": "Finance Desk & collections",
    "followup": "Follow-up", "products": "Products & courses", "incentives": "Incentives",
    "invoices": "Invoices & payment details", "team": "Team directory", "reports": "Reports",
    "batches": "Batches", "analytics": "Course analytics", "messages": "Messages & reminders",
    "expenses": "Expense records", "my-students": "My students",
}
DATA_ACCESS_OPTIONS = {
    "company-revenue": "Company-wide revenue and cash totals", "sales-values": "Course prices and order values",
    "payment-amounts": "Receipt, refund and installment amounts", "outstanding-balances": "Outstanding balances and amount due",
    "commission-percentages": "Commission rates and split percentages", "own-incentives": "Own incentive earned, due and paid",
    "team-incentives": "Team incentive totals and member breakdown", "student-contacts": "Student phone numbers and email addresses",
    "invoice-values": "Invoice prices, received amounts and balances", "target-estimates": "Estimated income and incentive on targets",
}
DATA_ACCESS_GROUPS = {
    "company-revenue": "Financial visibility", "sales-values": "Financial visibility", "payment-amounts": "Financial visibility",
    "outstanding-balances": "Financial visibility", "invoice-values": "Financial visibility",
    "commission-percentages": "Incentives", "own-incentives": "Incentives", "team-incentives": "Incentives",
    "target-estimates": "Incentives", "student-contacts": "Student information",
}
DEFAULT_ROLE_ACCESS = {
    "manager": ["overview", "targets", "collections", "followup", "products", "incentives", "invoices", "team", "reports", "batches", "analytics", "messages", "expenses"],
    "employee": ["overview", "targets", "followup", "products", "invoices", "batches", "analytics", "messages", "incentives", "my-students", "expenses"],
}
DEFAULT_ROLE_DATA_ACCESS = {
    "manager": ["payment-amounts", "outstanding-balances", "commission-percentages", "own-incentives", "team-incentives", "student-contacts", "invoice-values"],
    "employee": ["sales-values", "payment-amounts", "outstanding-balances", "own-incentives", "student-contacts", "invoice-values"],
}


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


def _minor(value):
    try:
        amount = Decimal(str(value or 0))
        if not amount.is_finite() or amount < 0:
            raise ValueError
        return int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Enter a valid non-negative amount")


def _boolean(value):
    return value is True or str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _json_list(value):
    try:
        result = json.loads(value or "[]")
        return result if isinstance(result, list) else []
    except (ValueError, TypeError):
        return []


def _month_key(value):
    try:
        parsed = date.fromisoformat(str(value or date.today().strftime("%Y-%m"))[:7] + "-01")
        return parsed.strftime("%Y-%m")
    except (TypeError, ValueError):
        raise ValueError("Choose a valid target month")


async def _setting(db, key, default):
    row = await _first(db.prepare("SELECT value FROM settings WHERE key=?").bind(key))
    return row["value"] if row else str(default)


async def _audit(db, actor_id, action, entity, entity_id=None):
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,?,?,?)").bind(
        actor_id, action, entity, entity_id).run()


def _plain(value):
    if value is None:
        return None
    convert = getattr(value, "to_py", None)
    if callable(convert):
        try:
            return convert()
        except Exception:
            pass
    return value


async def _all(statement):
    return await statement.all()


def _rows(result):
    try:
        values = result.results
    except (AttributeError, TypeError):
        values = result["results"]
    values = _plain(values)
    return [_plain(row) for row in values]


async def _first(statement):
    return _plain(await statement.first())


async def _signed_in_user(request: Request):
    cookie = request.cookies.get("offtune_session")
    if not cookie:
        return None
    return await _first(_env(request).DB.prepare(
        "SELECT u.id,u.name,u.email,u.role,u.manager_id,u.job_title,u.designation_id,u.avatar_data "
        "FROM sessions s JOIN users u ON u.id=COALESCE(s.act_as_user_id,s.user_id) "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
    ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())))


async def _require_user(request: Request, roles=None):
    user = await _signed_in_user(request)
    if not user:
        return None, JSONResponse({"error": "Sign in to continue"}, status_code=401)
    if roles and user["role"] not in roles:
        return None, JSONResponse({"error": "You do not have access to this section"}, status_code=403)
    if request.method not in ("GET", "HEAD"):
        cookie = request.cookies.get("offtune_session")
        session = await _first(_env(request).DB.prepare(
            "SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?"
        ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())))
        if not session or not hmac.compare_digest(
            str(request.headers.get("x-csrf-token", "")), str(session["csrf"])
        ):
            return None, JSONResponse({"error": "Refresh the page and try again"}, status_code=403)
    return user, None


@app.get("/healthz")
async def health(request: Request):
    try:
        result = await _first(_env(request).DB.prepare(
            "SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ))
        return {"status": "ready", "schema_tables": result["count"]}
    except Exception:
        return JSONResponse({"status": "database_unavailable"}, status_code=503)


@app.get("/api/auth/session")
async def auth_session(request: Request):
    db = _env(request).DB
    count = await _first(db.prepare("SELECT COUNT(*) AS n FROM users"))
    cookie = request.cookies.get("offtune_session")
    if not cookie:
        return {"setup_required": count["n"] == 0, "user": None, "csrf": None,
                "workspace_preview": False, "owner_name": None}
    session = await _first(db.prepare(
        "SELECT s.csrf,s.expires_at,s.act_as_user_id,owner.name owner_name,u.id,u.name,u.email,u.role,u.manager_id,u.job_title,"
        "u.designation_id,u.avatar_data,d.name designation,d.permissions_json,d.data_permissions_json "
        "FROM sessions s JOIN users owner ON owner.id=s.user_id "
        "JOIN users u ON u.id=COALESCE(s.act_as_user_id,s.user_id) LEFT JOIN designations d ON d.id=u.designation_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND owner.is_active=1 AND u.is_active=1"
    ).bind(hashlib.sha256(cookie.encode()).hexdigest(), int(time.time())))
    if not session:
        return {"setup_required": count["n"] == 0, "user": None, "csrf": None,
                "workspace_preview": False, "owner_name": None}
    default_permissions = list(ACCESS_FEATURES) if session["role"] == "owner" else DEFAULT_ROLE_ACCESS.get(session["role"], [])
    default_data_permissions = list(DATA_ACCESS_OPTIONS) if session["role"] == "owner" else DEFAULT_ROLE_DATA_ACCESS.get(session["role"], [])
    permissions = _json_list(session["permissions_json"]) if session["designation_id"] else default_permissions
    data_permissions = _json_list(session["data_permissions_json"]) if session["designation_id"] else default_data_permissions
    return {"setup_required": False, "user": {"id": session["id"], "name": session["name"],
            "email": session["email"], "role": session["role"], "manager_id": session["manager_id"],
            "job_title": session["job_title"] or "", "designation_id": session["designation_id"],
            "designation": session["job_title"] or session["designation"] or session["role"].title(),
            "permissions": permissions,
            "data_permissions": data_permissions,
            "avatar_data": session["avatar_data"] or ""}, "csrf": session["csrf"],
            "workspace_preview": bool(session["act_as_user_id"]),
            "owner_name": session["owner_name"] if session["act_as_user_id"] else None}


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
            for r in _rows(rows)]


@app.post("/api/products")
async def create_product(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        sku = str(data.get("sku", "")).strip().upper()[:40]
        name = str(data.get("name", "")).strip()[:160]
        kind = str(data.get("product_type", ""))
        price = _minor(data.get("price"))
        rate = Decimal(str(data.get("commission_rate", 5)))
        if not sku or not name or kind not in ("course", "sample_pack", "digital_product"):
            raise ValueError("Enter SKU, product name and a valid product type")
        if not rate.is_finite() or rate < 0 or rate > 100:
            raise ValueError("Commission rate must be between 0 and 100")
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Check the product details"}, status_code=400)
    db = _env(request).DB
    try:
        created = await _first(db.prepare(
            "INSERT INTO products(sku,name,product_type,price_minor,currency,installment_allowed,commission_rate,active) "
            "VALUES(?,?,?,?,?,?,?,?) RETURNING id"
        ).bind(sku, name, kind, price, str(data.get("currency") or "INR")[:3], int(_boolean(data.get("installment_allowed"))), float(rate), int(price > 0)))
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'created','product',?)").bind(user["id"], created["id"]).run()
    except Exception:
        return JSONResponse({"error": "Product was not saved. Check that its SKU is unique and try again."}, status_code=409)
    return JSONResponse({"id": created["id"]}, status_code=201)


@app.post("/api/products/update")
async def update_product(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        product_id = int(data.get("id", 0))
        name = str(data.get("name", "")).strip()[:160]
        sku = str(data.get("sku", "")).strip().upper()[:40]
        price = _minor(data.get("price"))
        rate = Decimal(str(data.get("commission_rate", 5)))
        if product_id < 1 or not name or not sku:
            raise ValueError("Enter a product name and SKU")
        if not rate.is_finite() or rate < 0 or rate > 100:
            raise ValueError("Commission rate must be between 0 and 100")
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Check the product details"}, status_code=400)
    db = _env(request).DB
    product = await _first(db.prepare("SELECT id FROM products WHERE id=?").bind(product_id))
    if not product:
        return JSONResponse({"error": "Product not found"}, status_code=404)
    try:
        await db.prepare("UPDATE products SET name=?,sku=?,price_minor=?,commission_rate=?,installment_allowed=?,active=? WHERE id=?").bind(
            name, sku, price, float(rate), int(_boolean(data.get("installment_allowed"))), int(price > 0 and _boolean(data.get("active"))), product_id).run()
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','product',?)").bind(user["id"], product_id).run()
    except Exception:
        return JSONResponse({"error": "Product was not updated. Check that its SKU is unique and try again."}, status_code=409)
    return {"ok": True}


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
    return _rows(rows)


@app.post("/api/batches")
async def save_batch(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        batch_id = int(data.get("id") or 0)
        name = str(data.get("name", "")).strip()[:120]
        product_id = int(data.get("product_id", 0))
        start = date.fromisoformat(str(data["start_date"])) if data.get("start_date") else None
        end = date.fromisoformat(str(data["end_date"])) if data.get("end_date") else None
        if not name:
            raise ValueError("Enter a batch name")
        if start and end and end < start:
            raise ValueError("Batch end date cannot be before start date")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the batch details"}, status_code=400)
    db = _env(request).DB
    product = await _first(db.prepare("SELECT id,product_type,active FROM products WHERE id=?").bind(product_id))
    if not product or product["product_type"] != "course":
        return JSONResponse({"error": "Choose an active course for this batch"}, status_code=400)
    status = "active" if product["active"] and _boolean(data.get("active")) else "setup_needed"
    try:
        if batch_id:
            existing = await _first(db.prepare("SELECT id FROM batches WHERE id=?").bind(batch_id))
            if not existing:
                return JSONResponse({"error": "Batch not found"}, status_code=404)
            await db.prepare("UPDATE batches SET name=?,product_id=?,start_date=?,end_date=?,status=? WHERE id=?").bind(
                name, product_id, start.isoformat() if start else None, end.isoformat() if end else None, status, batch_id).run()
            await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','batch',?)").bind(user["id"], batch_id).run()
            return {"ok": True, "id": batch_id}
        created = await _first(db.prepare(
            "INSERT INTO batches(name,product_id,start_date,end_date,status) VALUES(?,?,?,?,?) RETURNING id"
        ).bind(name, product_id, start.isoformat() if start else None, end.isoformat() if end else None, status))
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'created','batch',?)").bind(user["id"], created["id"]).run()
        return JSONResponse({"id": created["id"]}, status_code=201)
    except Exception:
        return JSONResponse({"error": "Batch was not saved. Check the course and try again."}, status_code=409)


@app.post("/api/batches/remove")
async def remove_batch(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        batch_id = int(data.get("id", 0))
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the batch removal")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose a batch"}, status_code=400)
    db = _env(request).DB
    batch = await _first(db.prepare("SELECT id FROM batches WHERE id=?").bind(batch_id))
    if not batch:
        return JSONResponse({"error": "Batch not found"}, status_code=404)
    links = await _first(db.prepare("SELECT COUNT(*) count FROM order_items WHERE batch_id=?").bind(batch_id))
    archived = int(links["count"] or 0) > 0
    if archived:
        await db.prepare("UPDATE batches SET status='archived' WHERE id=?").bind(batch_id).run()
    else:
        await db.prepare("DELETE FROM batches WHERE id=?").bind(batch_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,?, 'batch',?)").bind(
        user["id"], "archived" if archived else "deleted", batch_id).run()
    return {"ok": True, "archived": archived}


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
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds = [user["id"]]
    rows = await db.prepare(
        "SELECT o.*,c.name customer_name,c.phone,c.email,u.name employee_name FROM orders o "
        "JOIN customers c ON c.id=o.customer_id LEFT JOIN users u ON u.id=o.employee_id "
        "WHERE o.status!='void'" + scope + " ORDER BY o.order_date DESC,o.id DESC"
    ).bind(*binds).all()
    result = []
    for order in _rows(rows):
        item_rows = await db.prepare(
            "SELECT oi.id order_item_id,p.id product_id,p.name,p.product_type,oi.quantity,oi.unit_price_minor,"
            "oi.discount_minor,oi.line_total_minor,b.id batch_id,b.name batch_name FROM order_items oi "
            "JOIN products p ON p.id=oi.product_id LEFT JOIN batches b ON b.id=oi.batch_id "
            "WHERE oi.order_id=? ORDER BY oi.id"
        ).bind(order["id"]).all()
        receipts = await _first(db.prepare(
            "SELECT COALESCE(SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END),0) n "
            "FROM payments WHERE order_id=?"
        ).bind(order["id"]))
        received = int(receipts["n"] or 0)
        total = int(order["total_minor"] or 0)
        items = _rows(item_rows)
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
        manager_can_manage = False
        if user["role"] == "manager" and order["employee_id"] is not None:
            team_access = await _first(db.prepare(
                "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 "
                "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) "
                "SELECT EXISTS(SELECT 1 FROM team WHERE id=?) member"
            ).bind(user["id"], order["employee_id"]))
            manager_can_manage = bool(team_access and team_access["member"])
        base = {"id": order["id"], "customer_id": order["customer_id"], "employee_id": order["employee_id"],
                "can_manage": user["role"] == "owner" or manager_can_manage or (user["role"] == "employee" and order["employee_id"] == user["id"]),
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


@app.get("/api/customers/{customer_id}")
async def customer_profile(customer_id: int, request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    customer = await _first(db.prepare("SELECT id,name,phone,email,created_at FROM customers WHERE id=?").bind(customer_id))
    if not customer:
        return JSONResponse({"error": "Student not found"}, status_code=404)
    customer_orders = [row for row in await orders(request) if int(row["customer_id"]) == customer_id]
    if not customer_orders:
        return JSONResponse({"error": "Student not found in your workspace"}, status_code=404)
    order_ids = {int(row["id"]) for row in customer_orders}
    installment_rows = [row for row in await installments(request) if row["order_no"] in {o["order_no"] for o in customer_orders}]
    payment_rows = [row for row in await payments(request) if int(row["order_id"]) in order_ids]
    if user["role"] == "employee":
        batch_rows = await db.prepare(
            "SELECT DISTINCT b.id,b.name,b.product_id,b.status FROM batches b JOIN order_items oi ON oi.batch_id=b.id "
            "JOIN orders o ON o.id=oi.order_id WHERE o.employee_id=? AND o.customer_id=? ORDER BY b.name"
        ).bind(user["id"], customer_id).all()
    else:
        batch_rows = await db.prepare("SELECT id,name,product_id,status FROM batches ORDER BY name").all()
    return {"student": {"id": customer["id"], "name": customer["name"], "phone": customer["phone"] or "",
                         "email": customer["email"] or "", "created_at": customer["created_at"]},
            "orders": customer_orders, "installments": installment_rows, "payments": payment_rows,
            "batches": [{"id": row["id"], "name": row["name"], "product_id": row["product_id"], "status": row["status"]} for row in _rows(batch_rows)]}


@app.post("/api/orders")
async def record_sale(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        customer = data.get("customer") or {}
        items = data.get("items") or []
        if not str(customer.get("name", "")).strip() or not items or len(items) > 20:
            raise ValueError("Add a customer and between one and 20 products")
        customer_name = str(customer["name"]).strip()[:120]
        phone = str(customer.get("phone", "")).strip()[:40]
        email = str(customer.get("email", "")).strip()[:160]
        order_date = date.fromisoformat(str(data.get("order_date") or date.today().isoformat()))
        if order_date > date.today():
            raise ValueError("Sale date cannot be in the future")
        product_lines = []
        subtotal = 0
        db = _env(request).DB
        for item in items:
            product_id = int(item.get("product_id", 0))
            product = await _first(db.prepare(
                "SELECT id,name,sku,product_type,price_minor,currency,installment_allowed,commission_rate "
                "FROM products WHERE id=? AND active=1 AND price_minor>0"
            ).bind(product_id))
            if not product:
                raise ValueError("A selected product is unavailable")
            quantity = int(item.get("quantity", 1))
            discount_minor = _minor(item.get("discount", 0))
            if quantity < 1 or quantity > 100:
                raise ValueError("Quantity must be between one and 100")
            raw_minor = int(product["price_minor"]) * quantity
            if discount_minor > raw_minor:
                raise ValueError("A line discount cannot exceed its product price")
            batch_id = int(item["batch_id"]) if item.get("batch_id") else None
            if batch_id:
                batch = await _first(db.prepare(
                    "SELECT id,product_id,status FROM batches WHERE id=?"
                ).bind(batch_id))
                if not batch or batch["product_id"] != product_id or batch["status"] != "active" or product["product_type"] != "course":
                    raise ValueError("Choose an active batch for the selected course")
            line_total = raw_minor - discount_minor
            subtotal += line_total
            product_lines.append((product, quantity, discount_minor, line_total, batch_id))
        discount_mode = str(data.get("discount_mode", "amount"))
        discount_value = data.get("discount_value", data.get("discount", 0))
        if discount_mode == "percent":
            percentage = Decimal(str(discount_value or 0))
            if not percentage.is_finite() or percentage < 0 or percentage > 100:
                raise ValueError("Discount percentage must be from zero to 100")
            order_discount = int((Decimal(subtotal) * percentage / Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        elif discount_mode == "amount":
            order_discount = _minor(discount_value)
        else:
            raise ValueError("Choose a valid order discount type")
        if order_discount > subtotal:
            raise ValueError("Order discount cannot exceed subtotal")
        total = subtotal - order_discount
        booking = _minor(data.get("booking_amount", 0))
        admission = _minor(data.get("admission_fee", 0))
        if booking + admission > total:
            raise ValueError("Booking and admission cannot exceed the sale total")
        count = int(data.get("installment_count", 0))
        if count < 0 or count > 24:
            raise ValueError("Choose between zero and 24 monthly EMIs")
        if total == booking + admission:
            count = 0
        if count and any(not bool(line[0]["installment_allowed"]) for line in product_lines):
            raise ValueError("A selected product does not allow EMI payments")
        course_start = date.fromisoformat(str(data["course_start_date"])) if data.get("course_start_date") else None
        admission_due = date.fromisoformat(str(data["admission_due_date"])) if data.get("admission_due_date") else (course_start or order_date)
        first_due = date.fromisoformat(str(data["first_due_date"])) if count and data.get("first_due_date") else (course_start or order_date) if count else None
        due_day = int(data.get("emi_due_day") or (first_due.day if first_due else 1))
        if not 1 <= due_day <= 31:
            raise ValueError("Monthly EMI date must be from one to 31")
        admission_paid = data.get("admission_paid") is True or str(data.get("admission_paid", "")).lower() in ("true", "1", "yes")
        booking_paid = data.get("booking_collected") is True or str(data.get("booking_collected", "")).lower() in ("true", "1", "yes")
        booking_paid_on = date.fromisoformat(str(data.get("booking_paid_on") or order_date.isoformat()))
        admission_paid_on = date.fromisoformat(str(data.get("admission_paid_on") or order_date.isoformat()))
        if booking_paid_on > date.today() or admission_paid_on > date.today():
            raise ValueError("A collected payment cannot be dated in the future")
        if count:
            anchor = admission_paid_on if admission_paid and admission else admission_due if admission else order_date
            if (first_due.year, first_due.month) <= (anchor.year, anchor.month):
                raise ValueError("The first EMI must be in a month after the admission due date")
        enrollment = str(data.get("enrollment_status", "booked"))
        if enrollment not in ("booked", "admitted"):
            raise ValueError("Choose Booked or Admitted status")
        if admission_paid and admission:
            enrollment = "admitted"
        settings_result = await db.prepare(
            "SELECT key,value FROM settings WHERE key IN ('currency','invoice_prefix','next_invoice_number','business_name',"
            "'business_email','business_phone','business_website','business_address','business_tax_id','invoice_logo_data')"
        ).all()
        settings_map = {r["key"]: r["value"] for r in _rows(settings_result)}
        currency = str(data.get("currency") or settings_map.get("currency") or product_lines[0][0]["currency"] or "INR")[:3]
        invoice_prefix = str(settings_map.get("invoice_prefix", "INV"))[:20]
        invoice_number = max(1, int(settings_map.get("next_invoice_number", "1001")))
        invoice_no = f"{invoice_prefix}-{invoice_number:05d}"
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Check the sale details"}, status_code=400)

    employee_id = user["id"] if user["role"] in ("manager", "employee") else None
    if user["role"] == "employee" and data.get("employee_id") not in (None, ""):
        return JSONResponse({"error": "Employee sales are assigned to their own workspace"}, status_code=403)
    temp_no = "TMP-" + secrets.token_hex(10)
    order_total = total
    order_items_sql = "INSERT INTO order_items(order_id,product_id,batch_id,quantity,unit_price_minor,commission_rate,discount_minor,line_total_minor) SELECT id,?,?,?,?,?,?,? FROM orders WHERE order_no=?"
    statements = [
        db.prepare("INSERT INTO customers(name,phone,email) VALUES(?,?,?)").bind(customer_name, phone, email),
        db.prepare("INSERT INTO orders(order_no,customer_id,employee_id,order_date,status,currency,subtotal_minor,discount_minor,discount_label,total_minor,installment_count,admission_minor,emi_due_day,first_due_date,enrollment_status,booking_minor,course_start_date,admission_due_date,notes,created_by) VALUES(?,last_insert_rowid(),?,?,'active',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(
            temp_no, employee_id, order_date.isoformat(), currency, subtotal, order_discount,
            str(data.get("discount_label", "")).strip()[:60], order_total, count, admission, due_day,
            first_due.isoformat() if first_due else None, enrollment, booking,
            course_start.isoformat() if course_start else None, admission_due.isoformat(),
            str(data.get("notes", ""))[:500], user["id"]),
    ]
    for product, quantity, line_discount, line_total, batch_id in product_lines:
        statements.append(db.prepare(order_items_sql).bind(product["id"], batch_id, quantity,
            product["price_minor"], product["commission_rate"], line_discount, line_total, temp_no))
    if booking:
        statements.append(db.prepare(
            "INSERT INTO installments(order_id,installment_no,due_date,amount_minor) SELECT id,-1,?,? FROM orders WHERE order_no=?"
        ).bind(order_date.isoformat(), booking, temp_no))
    if admission:
        statements.append(db.prepare(
            "INSERT INTO installments(order_id,installment_no,due_date,amount_minor) SELECT id,0,?,? FROM orders WHERE order_no=?"
        ).bind(admission_due.isoformat(), admission, temp_no))
    emi_balance = total - booking - admission
    if count:
        base, remainder = divmod(emi_balance, count)
        for index in range(count):
            month_index = first_due.year * 12 + first_due.month - 1 + index
            year, month0 = divmod(month_index, 12)
            month = month0 + 1
            next_month = date(year + (month == 12), month % 12 + 1, 1)
            emi_date = min(due_day, (next_month - timedelta(days=1)).day)
            due = date(year, month, emi_date).isoformat()
            statements.append(db.prepare(
                "INSERT INTO installments(order_id,installment_no,due_date,amount_minor) SELECT id,?,?,? FROM orders WHERE order_no=?"
            ).bind(index + 1, due, base + (1 if index < remainder else 0), temp_no))
    elif emi_balance:
        statements.append(db.prepare(
            "INSERT INTO installments(order_id,installment_no,due_date,amount_minor) SELECT id,1,?,? FROM orders WHERE order_no=?"
        ).bind(admission_due.isoformat(), emi_balance, temp_no))
    for collected, amount, paid_on, method, reference, label, installment_no in (
        (booking_paid, booking, booking_paid_on, data.get("booking_method", "Other"), data.get("booking_reference", ""), "Booking deposit collected at sale", -1),
        (admission_paid, admission, admission_paid_on, data.get("admission_method", "Other"), data.get("admission_reference", ""), "Admission fee collected at sale", 0),
    ):
        if collected and amount:
            statements.append(db.prepare(
                "INSERT INTO payments(order_id,payment_type,paid_on,amount_minor,method,reference,notes,created_by) "
                "SELECT id,'receipt',?,?,?,?,?,? FROM orders WHERE order_no=?"
            ).bind(paid_on.isoformat(), amount, str(method)[:60], str(reference)[:120], label, user["id"], temp_no))
            statements.append(db.prepare(
                "INSERT INTO payment_allocations(payment_id,installment_id,amount_minor) "
                "SELECT p.id,i.id,p.amount_minor FROM payments p JOIN installments i ON i.order_id=p.order_id "
                "WHERE p.order_id=(SELECT id FROM orders WHERE order_no=?) AND p.notes=? AND i.installment_no=? "
                "ORDER BY p.id DESC LIMIT 1"
            ).bind(temp_no, label, installment_no))
    statements.extend([
        db.prepare("INSERT INTO invoices(order_id,invoice_no,issued_on,status,created_by) SELECT id,?,?, 'draft',? FROM orders WHERE order_no=?").bind(invoice_no, date.today().isoformat(), user["id"], temp_no),
        db.prepare("INSERT INTO invoice_profiles(invoice_id,business_name,business_email,business_phone,business_website,business_address,business_tax_id,logo_data,customer_name,customer_phone,customer_email,currency,order_no,order_date,subtotal_minor,discount_minor,tax_minor,total_minor) SELECT i.id,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? FROM invoices i JOIN orders o ON o.id=i.order_id JOIN customers c ON c.id=o.customer_id WHERE i.invoice_no=?").bind(
            settings_map.get("business_name", "OFFTune Business Desk"), settings_map.get("business_email", ""),
            settings_map.get("business_phone", ""), settings_map.get("business_website", ""), settings_map.get("business_address", ""),
            settings_map.get("business_tax_id", ""), settings_map.get("invoice_logo_data", ""), customer_name, phone, email,
            currency, "", order_date.isoformat(), subtotal, order_discount, 0, order_total, invoice_no),
        db.prepare("INSERT INTO invoice_items(invoice_id,product_type,sku,description,batch_name,quantity,unit_price_minor,discount_minor,line_total_minor) SELECT i.id,p.product_type,p.sku,p.name,COALESCE(b.name,''),oi.quantity,oi.unit_price_minor,oi.discount_minor,oi.line_total_minor FROM invoices i JOIN order_items oi ON oi.order_id=i.order_id JOIN products p ON p.id=oi.product_id LEFT JOIN batches b ON b.id=oi.batch_id WHERE i.invoice_no=?").bind(invoice_no),
        db.prepare("UPDATE orders SET order_no='ORD-'||substr(replace(order_date,'-',''),3,4)||'-'||printf('%05d',id) WHERE order_no=?").bind(temp_no),
        db.prepare("UPDATE invoice_profiles SET order_no=(SELECT o.order_no FROM invoices i JOIN orders o ON o.id=i.order_id WHERE i.id=invoice_profiles.invoice_id) WHERE invoice_id=(SELECT id FROM invoices WHERE invoice_no=?)").bind(invoice_no),
        db.prepare("INSERT INTO settings(key,value) VALUES('next_invoice_number',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(str(invoice_number + 1)),
        db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) SELECT ?,'created','order',order_id FROM invoices WHERE invoice_no=?").bind(user["id"], invoice_no),
    ])
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Sale was not saved; no partial sale or invoice changes were kept. Check the details and try again."}, status_code=409)
    saved = await _first(db.prepare(
        "SELECT o.id,o.order_no,i.id invoice_id,i.invoice_no FROM orders o JOIN invoices i ON i.order_id=o.id WHERE i.invoice_no=?"
    ).bind(invoice_no))
    if not saved:
        return JSONResponse({"error": "Sale saved, but its invoice could not be loaded. Refresh the invoice register."}, status_code=500)
    return JSONResponse({"id": saved["id"], "order_no": saved["order_no"], "invoice_created": True,
        "invoice_id": saved["invoice_id"], "invoice_no": saved["invoice_no"]}, status_code=201)


@app.get("/api/payments")
async def payments(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = ""
    binds = []
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds = [user["id"], user["id"]]
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds = [user["id"]]
    rows = await db.prepare(
        "SELECT p.*,o.customer_id,o.order_no,c.name customer,u.name employee_name FROM payments p "
        "JOIN orders o ON o.id=p.order_id JOIN customers c ON c.id=o.customer_id "
        "LEFT JOIN users u ON u.id=o.employee_id WHERE 1=1" + scope + " ORDER BY p.paid_on DESC,p.id DESC"
    ).bind(*binds).all()
    result = []
    for row in _rows(rows):
        allocated = await db.prepare(
            "SELECT i.installment_no,o.installment_count,SUM(a.amount_minor) amount_minor "
            "FROM payment_allocations a JOIN installments i ON i.id=a.installment_id "
            "JOIN orders o ON o.id=i.order_id WHERE a.payment_id=? GROUP BY i.id ORDER BY i.installment_no"
        ).bind(row["id"]).all()
        allocations = []
        for item in _rows(allocated):
            number = item["installment_no"]
            label = "Booking deposit" if number == -1 else "Admission fee" if number == 0 else f"EMI {number}" if item["installment_count"] else "Balance due"
            allocations.append({"label": label, "amount": _money(item["amount_minor"])})
        result.append({"id": row["id"], "order_id": row["order_id"], "customer_id": row["customer_id"],
            "order_no": row["order_no"], "customer": row["customer"], "employee": row["employee_name"],
            "type": row["payment_type"], "date": row["paid_on"], "recorded_at": str(row["created_at"]).replace(" ", "T") + "Z",
            "amount": _money(row["amount_minor"]), "method": row["method"], "reference": row["reference"],
            "allocations": allocations})
    return result


@app.get("/api/installments")
async def installments(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = ""
    binds = []
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds = [user["id"], user["id"]]
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds = [user["id"]]
    rows = await db.prepare(
        "SELECT i.*,o.customer_id,o.order_no,o.employee_id,o.installment_count,o.enrollment_status,"
        "c.name customer,c.phone customer_phone,c.email customer_email,u.name employee,"
        "COALESCE((SELECT GROUP_CONCAT(DISTINCT b.name) FROM order_items oi JOIN batches b ON b.id=oi.batch_id WHERE oi.order_id=i.order_id),'Not assigned') batch_name "
        "FROM installments i JOIN orders o ON o.id=i.order_id JOIN customers c ON c.id=o.customer_id "
        "LEFT JOIN users u ON u.id=o.employee_id WHERE o.status='active'" + scope +
        " ORDER BY i.due_date,i.order_id,i.installment_no"
    ).bind(*binds).all()
    result = []
    for row in _rows(rows):
        paid = await _first(db.prepare("SELECT COALESCE(SUM(amount_minor),0) amount FROM payment_allocations WHERE installment_id=?").bind(row["id"]))
        amount_paid = int(paid["amount"] or 0)
        balance = max(0, int(row["amount_minor"]) - amount_paid)
        number = row["installment_no"]
        label = "Booking deposit" if number == -1 else "Admission fee" if number == 0 else f"EMI {number}" if row["installment_count"] else "Balance due"
        logs = await db.prepare(
            "SELECT f.outcome,f.note,f.promised_date,f.next_followup_at,f.created_at,u.name user_name "
            "FROM followup_logs f LEFT JOIN users u ON u.id=f.user_id WHERE f.installment_id=? ORDER BY f.id DESC LIMIT 8"
        ).bind(row["id"]).all()
        manager_can_manage = True
        if user["role"] == "manager":
            team_access = await _first(db.prepare(
                "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 "
                "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) "
                "SELECT EXISTS(SELECT 1 FROM team WHERE id=?) member"
            ).bind(user["id"], row["employee_id"]))
            manager_can_manage = bool(team_access and team_access["member"])
        can_manage = user["role"] == "owner" or (user["role"] == "manager" and manager_can_manage) or (user["role"] == "employee" and row["employee_id"] == user["id"])
        result.append({"id": row["id"], "can_manage": can_manage, "customer_id": row["customer_id"],
            "order_no": row["order_no"], "customer": row["customer"], "phone": row["customer_phone"],
            "email": row["customer_email"], "employee": row["employee"], "batch": row["batch_name"],
            "enrollment_status": row["enrollment_status"], "number": number, "label": label,
            "due_date": row["due_date"], "promised_date": row["promised_date"], "reason": row["reason"],
            "followup_outcome": row["followup_outcome"], "followup_at": row["followup_at"],
            "followup_history": [{"outcome": log["outcome"], "note": log["note"], "promised_date": log["promised_date"],
                "next_followup_at": log["next_followup_at"], "created_at": log["created_at"], "user": log["user_name"] or "Team"} for log in _rows(logs)],
            "amount": _money(row["amount_minor"]), "paid": _money(amount_paid), "balance": _money(balance),
            "status": "paid" if balance == 0 else "overdue" if row["due_date"] < date.today().isoformat() else "upcoming"})
    return result


@app.post("/api/payments")
async def record_payment(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        order_id = int(data.get("order_id", 0))
        amount = _minor(data.get("amount"))
        kind = str(data.get("payment_type", "receipt"))
        paid_on = date.fromisoformat(str(data.get("paid_on") or date.today().isoformat()))
        if amount <= 0:
            raise ValueError("Payment amount must be greater than zero")
        if kind not in ("receipt", "refund"):
            raise ValueError("Choose receipt or refund")
        if paid_on > date.today():
            raise ValueError("A receipt or refund cannot be dated in the future")
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Check the payment details"}, status_code=400)
    db = _env(request).DB
    scope = ""
    binds = [order_id]
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds.extend([user["id"], user["id"]])
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds.append(user["id"])
        if kind != "receipt":
            return JSONResponse({"error": "Employees can record receipts, not refunds"}, status_code=403)
    order = await _first(db.prepare(
        "SELECT o.id,o.employee_id,o.total_minor,o.admission_minor,o.booking_minor,o.installment_count "
        "FROM orders o WHERE o.id=? AND o.status='active'" + scope
    ).bind(*binds))
    if not order:
        return JSONResponse({"error": "Order not found in your workspace"}, status_code=404)
    current = await _first(db.prepare(
        "SELECT COALESCE(SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END),0) amount "
        "FROM payments WHERE order_id=?"
    ).bind(order_id))
    net_received = int(current["amount"] or 0)
    if kind == "receipt" and net_received + amount > int(order["total_minor"]):
        return JSONResponse({"error": "Receipt is greater than the remaining order balance"}, status_code=400)
    if kind == "refund" and amount > net_received:
        return JSONResponse({"error": "Refund cannot exceed the amount collected"}, status_code=400)
    schedules = await db.prepare(
        "SELECT i.id,i.installment_no,i.amount_minor,COALESCE(SUM(a.amount_minor),0) allocated "
        "FROM installments i LEFT JOIN payment_allocations a ON a.installment_id=i.id "
        "WHERE i.order_id=? GROUP BY i.id ORDER BY i.installment_no"
    ).bind(order_id).all()
    schedule_rows = _rows(schedules)
    if kind == "refund":
        schedule_rows.reverse()
    allocations = []
    remaining = amount
    for item in schedule_rows:
        paid = int(item["allocated"] or 0)
        capacity = max(0, int(item["amount_minor"]) - paid) if kind == "receipt" else max(0, paid)
        applied = min(remaining, capacity)
        if applied:
            allocations.append((item["id"], applied if kind == "receipt" else -applied))
            remaining -= applied
        if not remaining:
            break
    if remaining:
        return JSONResponse({"error": "Payment could not be fully assigned to the order schedule"}, status_code=409)
    method = str(data.get("method", "Other"))[:60]
    reference = str(data.get("reference", ""))[:120]
    notes = str(data.get("notes", ""))[:500]
    statements = [db.prepare(
        "INSERT INTO payments(id,order_id,payment_type,paid_on,amount_minor,method,reference,notes,created_by) "
        "SELECT COALESCE(MAX(id),0)+1,?,?,?,?,?,?,?,? FROM payments"
    ).bind(order_id, kind, paid_on.isoformat(), amount, method, reference, notes, user["id"])]
    for installment_id, allocated in allocations:
        statements.append(db.prepare(
            "INSERT INTO payment_allocations(payment_id,installment_id,amount_minor) "
            "SELECT (SELECT MAX(id) FROM payments),?,?"
        ).bind(installment_id, allocated))
    statements.extend([
        db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) SELECT ?,?,'payment',MAX(id) FROM payments").bind(user["id"], kind),
        db.prepare("UPDATE orders SET enrollment_status=CASE WHEN ? >= booking_minor+admission_minor AND admission_minor>0 THEN 'admitted' WHEN admission_minor>0 THEN 'booked' ELSE enrollment_status END WHERE id=?").bind(net_received + (amount if kind == "receipt" else -amount), order_id),
    ])
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Payment was not saved; no partial receipt or schedule changes were kept. Please retry."}, status_code=409)
    saved = await _first(db.prepare("SELECT MAX(id) id FROM payments WHERE order_id=? AND created_by=?").bind(order_id, user["id"]))
    return JSONResponse({"id": saved["id"] if saved else None}, status_code=201)


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
    for row in _rows(rows):
        result.append({"id": row["id"], "name": row["name"], "email": row["email"],
            "role": row["role"], "job_title": row["job_title"] or "", "designation_id": row["designation_id"],
            "designation": row["job_title"] or row["designation"] or row["role"].title(),
            "permissions": _json_list(row["permissions_json"]),
            "data_permissions": _json_list(row["data_permissions_json"]),
            "avatar_data": row["avatar_data"] or "", "manager_id": row["manager_id"],
            "manager_name": row["manager_name"], "active": bool(row["is_active"])})
    return result


@app.post("/api/team")
async def create_team_member(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()[:120]
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        if not name or "@" not in email or len(email) > 254:
            raise ValueError("Enter a valid name and work email")
        encoded_password = _hash_password(password)
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the team member details"}, status_code=400)
    db = _env(request).DB
    designation_id = None
    manager_id = None
    if user["role"] == "manager":
        role = "employee"
        manager_id = user["id"]
        if data.get("role") not in (None, "", "employee"):
            return JSONResponse({"error": "Managers can add employee accounts only"}, status_code=403)
        if data.get("manager_id") not in (None, "", str(user["id"]), user["id"]):
            return JSONResponse({"error": "Employees added here must report directly to you"}, status_code=403)
    else:
        designation_id = int(data.get("designation_id") or 0) or None
        designation = await _first(db.prepare("SELECT id,name,role_class FROM designations WHERE id=?").bind(designation_id)) if designation_id else None
        role = designation["role_class"] if designation else str(data.get("role", "employee"))
        if designation_id and not designation:
            return JSONResponse({"error": "Choose a valid designation"}, status_code=400)
        if role not in ("manager", "employee"):
            return JSONResponse({"error": "Choose a valid designation"}, status_code=400)
        try:
            manager_id = int(data["manager_id"]) if data.get("manager_id") else None
        except (TypeError, ValueError):
            return JSONResponse({"error": "Choose a valid reporting manager"}, status_code=400)
        if manager_id:
            manager = await _first(db.prepare("SELECT id FROM users WHERE id=? AND role='manager' AND is_active=1").bind(manager_id))
            if not manager:
                return JSONResponse({"error": "Choose an active manager"}, status_code=400)
    job_title = str(data.get("job_title") or (designation["name"] if user["role"] == "owner" and designation else "Sales Executive" if role == "employee" else "Manager")).strip()[:80]
    try:
        created = await _first(db.prepare(
            "INSERT INTO users(name,email,password_hash,role,job_title,designation_id,manager_id) "
            "VALUES(?,?,?,?,?,?,?) RETURNING id"
        ).bind(name, email, encoded_password, role, job_title, designation_id, manager_id))
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'created','user',?)").bind(user["id"], created["id"]).run()
    except Exception:
        return JSONResponse({"error": "Team member was not added. Check that the email is not already in use."}, status_code=409)
    return JSONResponse({"id": created["id"]}, status_code=201)


@app.post("/api/team/profile")
async def update_team_profile(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        user_id = int(data.get("user_id", 0))
        name = str(data.get("name", "")).strip()[:120]
        email = str(data.get("email", "")).strip().lower()
        designation_id = int(data.get("designation_id") or 0) or None
        requested_role = str(data.get("role", ""))
        if not name or "@" not in email or len(email) > 254:
            raise ValueError("Enter a valid name and work email")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the team member details"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id,role,designation_id,job_title,manager_id FROM users WHERE id=? AND role IN ('manager','employee')").bind(user_id))
    if not person:
        return JSONResponse({"error": "Team member not found"}, status_code=404)
    if user["role"] == "manager" and (person["role"] != "employee" or person["manager_id"] != user["id"]):
        return JSONResponse({"error": "You can edit only your direct employees"}, status_code=403)
    designation = await _first(db.prepare("SELECT id,name,role_class FROM designations WHERE id=?").bind(designation_id)) if designation_id else None
    if designation_id and not designation:
        return JSONResponse({"error": "Choose a valid designation"}, status_code=400)
    role = designation["role_class"] if designation else requested_role or person["role"]
    if role not in ("manager", "employee"):
        return JSONResponse({"error": "Choose a valid designation"}, status_code=400)
    if user["role"] != "owner" and (role != person["role"] or (designation_id and designation_id != person["designation_id"])):
        return JSONResponse({"error": "Only the owner can change designation or access"}, status_code=403)
    title_value = data.get("job_title") if "job_title" in data else (designation["name"] if designation else person["job_title"])
    job_title = str(title_value or "").strip()[:80]
    if user["role"] == "manager":
        role = "employee"
        manager_id = user["id"]
    else:
        try:
            manager_id = int(data["manager_id"]) if data.get("manager_id") else None
        except (TypeError, ValueError):
            return JSONResponse({"error": "Choose a valid reporting manager"}, status_code=400)
    if manager_id == user_id:
        return JSONResponse({"error": "A team member cannot report to themselves"}, status_code=400)
    if manager_id:
        manager = await _first(db.prepare("SELECT id FROM users WHERE id=? AND role='manager' AND is_active=1").bind(manager_id))
        if not manager:
            return JSONResponse({"error": "Choose an active manager"}, status_code=400)
        descendant = await _first(db.prepare(
            "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? "
            "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id) "
            "SELECT EXISTS(SELECT 1 FROM team WHERE id=?) member"
        ).bind(user_id, manager_id))
        if descendant["member"]:
            return JSONResponse({"error": "That reporting change would create a loop"}, status_code=400)
    if person["role"] == "manager" and role != "manager":
        reports = await _first(db.prepare("SELECT COUNT(*) count FROM users WHERE manager_id=?").bind(user_id))
        if int(reports["count"] or 0):
            return JSONResponse({"error": "Move this manager’s direct reports before changing their access class"}, status_code=409)
    try:
        await db.prepare("UPDATE users SET name=?,email=?,role=?,job_title=?,designation_id=COALESCE(?,designation_id),manager_id=? WHERE id=?").bind(
            name, email, role, job_title, designation_id, manager_id, user_id).run()
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','team_member',?)").bind(user["id"], user_id).run()
    except Exception:
        return JSONResponse({"error": "Team member was not updated. Check that the email is unique."}, status_code=409)
    return {"ok": True}


@app.post("/api/team/update")
async def update_team_reporting(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        user_id = int(data.get("user_id", 0))
        manager_id = int(data["manager_id"]) if data.get("manager_id") else None
    except (ValueError, TypeError):
        return JSONResponse({"error": "Choose a valid team member and manager"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id,role,manager_id FROM users WHERE id=? AND role IN ('manager','employee')").bind(user_id))
    if not person:
        return JSONResponse({"error": "Team member not found"}, status_code=404)
    if user["role"] == "manager" and (person["role"] != "employee" or person["manager_id"] != user["id"]):
        return JSONResponse({"error": "You can change reporting only for your direct employees"}, status_code=403)
    if manager_id == user_id:
        return JSONResponse({"error": "A manager cannot report to themselves"}, status_code=400)
    if manager_id:
        manager = await _first(db.prepare("SELECT id FROM users WHERE id=? AND role='manager' AND is_active=1").bind(manager_id))
        if not manager:
            return JSONResponse({"error": "Choose an active manager"}, status_code=400)
        cycle = await _first(db.prepare(
            "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? "
            "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id) "
            "SELECT EXISTS(SELECT 1 FROM team WHERE id=?) member"
        ).bind(user_id, manager_id))
        if cycle["member"]:
            return JSONResponse({"error": "That reporting change would create a loop"}, status_code=400)
    await db.prepare("UPDATE users SET manager_id=? WHERE id=?").bind(manager_id, user_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'changed_reporting_line','user',?)").bind(user["id"], user_id).run()
    return {"ok": True}


@app.post("/api/team/status")
async def update_team_status(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        user_id = int(data.get("user_id", 0))
        active = _boolean(data.get("active"))
    except (ValueError, TypeError):
        return JSONResponse({"error": "Choose a valid team member"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id,role,is_active,manager_id FROM users WHERE id=? AND role IN ('manager','employee')").bind(user_id))
    if not person:
        return JSONResponse({"error": "Team member not found"}, status_code=404)
    if user["role"] == "manager" and (person["role"] != "employee" or person["manager_id"] != user["id"]):
        return JSONResponse({"error": "You can manage access only for your direct employees"}, status_code=403)
    if not active and person["role"] == "manager":
        direct = await _first(db.prepare("SELECT COUNT(*) count FROM users WHERE manager_id=?").bind(user_id))
        if int(direct["count"] or 0):
            return JSONResponse({"error": "Reassign this manager’s direct reports before removing them"}, status_code=409)
    await db.prepare("UPDATE users SET is_active=? WHERE id=?").bind(int(active), user_id).run()
    if not active:
        await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(user_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,?, 'team_member',?)").bind(
        user["id"], "activated" if active else "deactivated", user_id).run()
    return {"ok": True, "active": active}


@app.post("/api/team/reset-password")
async def reset_team_password(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        user_id = int(data.get("user_id", 0))
        password_hash = _hash_password(str(data.get("password", "")))
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose a valid team member and password"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id,manager_id FROM users WHERE id=? AND role IN ('manager','employee')").bind(user_id))
    if not person:
        return JSONResponse({"error": "Team member not found"}, status_code=404)
    if user["role"] == "manager" and person["manager_id"] != user["id"]:
        return JSONResponse({"error": "You can reset access only for your direct employees"}, status_code=403)
    await db.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(password_hash, user_id).run()
    await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(user_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'reset','team_member_password',?)").bind(user["id"], user_id).run()
    return {"ok": True}


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
        "direction": "inbox" if r["recipient_id"] == user["id"] else "sent"} for r in _rows(rows)]


def _designation_json(row):
    permissions = [key for key in _json_list(row["permissions_json"]) if key in ACCESS_FEATURES]
    data_permissions = [key for key in _json_list(row["data_permissions_json"]) if key in DATA_ACCESS_OPTIONS]
    return {"id": row["id"], "name": row["name"], "role_class": row["role_class"],
            "permissions": permissions, "data_permissions": data_permissions, "system": bool(row["is_system"])}


@app.get("/api/team/designations")
async def designations(request: Request):
    _, error = await _require_user(request, ("owner",))
    if error:
        return error
    rows = await _env(request).DB.prepare("SELECT * FROM designations ORDER BY is_system DESC,name COLLATE NOCASE").all()
    return {"features": [{"key": key, "label": label} for key, label in ACCESS_FEATURES.items()],
            "data_options": [{"key": key, "label": label, "group": DATA_ACCESS_GROUPS[key]} for key, label in DATA_ACCESS_OPTIONS.items()],
            "designations": [_designation_json(row) for row in _rows(rows)]}


@app.post("/api/team/designations")
async def save_designation(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        designation_id = int(data.get("id") or 0)
        name = str(data.get("name", "")).strip()[:80]
        role_class = str(data.get("role_class", "employee"))
        raw_permissions, raw_data = data.get("permissions", []), data.get("data_permissions", [])
        if not name or role_class not in ("manager", "employee") or not isinstance(raw_permissions, list) or not isinstance(raw_data, list):
            raise ValueError("Enter a designation, access class and feature choices")
        permitted_features = set(ACCESS_FEATURES)
        permitted_features.discard("team" if role_class == "employee" else "my-students")
        permissions = sorted({str(key) for key in raw_permissions if str(key) in permitted_features})
        data_permissions = sorted({str(key) for key in raw_data if str(key) in DATA_ACCESS_OPTIONS})
        if not permissions:
            raise ValueError("Enable at least one workspace feature")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check designation permissions"}, status_code=400)
    db = _env(request).DB
    try:
        if designation_id:
            existing = await _first(db.prepare("SELECT id,name,role_class,is_system FROM designations WHERE id=?").bind(designation_id))
            if not existing:
                return JSONResponse({"error": "Designation not found"}, status_code=404)
            if existing["is_system"] and (name != existing["name"] or role_class != existing["role_class"]):
                return JSONResponse({"error": "Built-in access classes keep their system name and reporting class"}, status_code=400)
            if existing["role_class"] == "manager" and role_class == "employee":
                reports = await _first(db.prepare("SELECT COUNT(*) count FROM users WHERE designation_id=? AND EXISTS(SELECT 1 FROM users direct WHERE direct.manager_id=users.id)").bind(designation_id))
                if int(reports["count"] or 0):
                    return JSONResponse({"error": "Reassign the direct reports of these managers before changing this designation"}, status_code=409)
            await db.prepare("UPDATE designations SET name=?,role_class=?,permissions_json=?,data_permissions_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(
                name, role_class, json.dumps(permissions), json.dumps(data_permissions), designation_id).run()
            if existing["role_class"] != role_class:
                await db.prepare("UPDATE users SET role=? WHERE designation_id=?").bind(role_class, designation_id).run()
            action = "updated"
        else:
            result = await _first(db.prepare("INSERT INTO designations(name,role_class,permissions_json,data_permissions_json) VALUES(?,?,?,?) RETURNING *").bind(
                name, role_class, json.dumps(permissions), json.dumps(data_permissions)))
            designation_id = result["id"]
            action = "created"
        saved = await _first(db.prepare("SELECT * FROM designations WHERE id=?").bind(designation_id))
        await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,?, 'designation',?)").bind(user["id"], action, designation_id).run()
    except Exception:
        return JSONResponse({"error": "Designation could not be saved. Check that its name is unique."}, status_code=409)
    return JSONResponse(_designation_json(saved), status_code=200 if data.get("id") else 201)


@app.post("/api/team/designations/delete")
async def delete_designation(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        designation_id = int(data.get("id", 0))
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the designation deletion")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose a designation"}, status_code=400)
    db = _env(request).DB
    designation = await _first(db.prepare("SELECT id,is_system FROM designations WHERE id=?").bind(designation_id))
    if not designation:
        return JSONResponse({"error": "Designation not found"}, status_code=404)
    if designation["is_system"]:
        return JSONResponse({"error": "Built-in designations cannot be removed"}, status_code=409)
    assigned = await _first(db.prepare("SELECT COUNT(*) count FROM users WHERE designation_id=?").bind(designation_id))
    if int(assigned["count"] or 0):
        return JSONResponse({"error": "Reassign every account using this designation before removing it"}, status_code=409)
    await db.prepare("DELETE FROM designations WHERE id=?").bind(designation_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'deleted','designation',?)").bind(user["id"], designation_id).run()
    return {"ok": True}


@app.get("/api/team/message-recipients")
async def team_message_recipients(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    if user["role"] == "owner":
        rows = await db.prepare("SELECT id,name,email,role FROM users WHERE role!='owner' AND is_active=1 ORDER BY name").all()
    elif user["role"] == "manager":
        rows = await db.prepare(
            "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 "
            "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) "
            "SELECT id,name,email,role FROM users WHERE id IN (SELECT id FROM team) OR role='owner' AND is_active=1 ORDER BY role,name"
        ).bind(user["id"]).all()
    else:
        rows = await db.prepare(
            "SELECT id,name,email,role FROM users WHERE is_active=1 AND (role='owner' OR (role='manager' AND id=?)) ORDER BY role,name"
        ).bind(user["manager_id"]).all()
    return _rows(rows)


@app.post("/api/team/messages")
async def send_team_message(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        recipient_id = int(data.get("recipient_id", 0))
        title = str(data.get("title", "")).strip()[:120]
        body = str(data.get("body", "")).strip()[:2000]
        remind_at = str(data.get("remind_at", "")).strip() or None
        if not title or not body:
            raise ValueError("Add a short title and message")
        if remind_at:
            from datetime import datetime
            remind_at = datetime.fromisoformat(remind_at).strftime("%Y-%m-%dT%H:%M")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the message details"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id,name,email,role,manager_id FROM users WHERE id=? AND is_active=1").bind(recipient_id))
    if not person:
        return JSONResponse({"error": "Choose an active recipient"}, status_code=404)
    allowed = user["role"] == "owner" and person["role"] != "owner"
    if user["role"] == "manager":
        scope = await _first(db.prepare(
            "WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 "
            "UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) "
            "SELECT EXISTS(SELECT 1 FROM team WHERE id=?) member"
        ).bind(user["id"], recipient_id))
        allowed = person["role"] == "owner" or bool(scope["member"])
    elif user["role"] == "employee":
        allowed = person["role"] == "owner" or (person["role"] == "manager" and person["id"] == user.get("manager_id"))
    if not allowed:
        return JSONResponse({"error": "You cannot message this team member"}, status_code=403)
    created = await _first(db.prepare(
        "INSERT INTO team_messages(sender_id,recipient_id,title,body,remind_at) VALUES(?,?,?,?,?) RETURNING id"
    ).bind(user["id"], recipient_id, title, body, remind_at))
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'sent_team_reminder','team_message',?)").bind(user["id"], created["id"]).run()
    return JSONResponse({"id": created["id"]}, status_code=201)


@app.post("/api/team/messages/complete")
async def complete_team_message(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        message_id = int((await request.json()).get("id", 0))
    except (ValueError, TypeError):
        return JSONResponse({"error": "Choose a message"}, status_code=400)
    db = _env(request).DB
    message = await _first(db.prepare("SELECT id,sender_id,recipient_id FROM team_messages WHERE id=?").bind(message_id))
    if not message:
        return JSONResponse({"error": "Message not found"}, status_code=404)
    if user["role"] != "owner" and user["id"] not in (message["sender_id"], message["recipient_id"]):
        return JSONResponse({"error": "You cannot update this message"}, status_code=403)
    if user["role"] != "owner" and user["id"] != message["recipient_id"]:
        return JSONResponse({"error": "Only the recipient can complete a message"}, status_code=403)
    await db.prepare("UPDATE team_messages SET read_at=COALESCE(read_at,CURRENT_TIMESTAMP),completed_at=COALESCE(completed_at,CURRENT_TIMESTAMP) WHERE id=?").bind(message_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'completed_team_reminder','team_message',?)").bind(user["id"], message_id).run()
    return {"ok": True}


@app.get("/api/expenses")
async def expenses(request: Request):
    _, error = await _require_user(request, ("owner",))
    if error:
        return error
    rows = await _env(request).DB.prepare("SELECT id,spent_on,category,description,amount_minor,method,recurring FROM expenses ORDER BY spent_on DESC,id DESC").all()
    return [{"id": r["id"], "date": r["spent_on"], "category": r["category"], "description": r["description"],
             "amount": _money(r["amount_minor"]), "method": r["method"], "recurring": bool(r["recurring"])} for r in _rows(rows)]


@app.post("/api/expenses")
async def create_expense(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        spent_on = date.fromisoformat(str(data.get("spent_on") or date.today().isoformat()))
        category = str(data.get("category", "Miscellaneous")).strip()[:80]
        description = str(data.get("description", "")).strip()[:240]
        amount = _minor(data.get("amount"))
        if not description:
            raise ValueError("Add an expense description")
        if spent_on > date.today():
            raise ValueError("Expense date cannot be in the future")
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Check the expense details"}, status_code=400)
    db = _env(request).DB
    saved = await _first(db.prepare(
        "INSERT INTO expenses(spent_on,category,description,amount_minor,method,recurring,notes,created_by) "
        "VALUES(?,?,?,?,?,?,?,?) RETURNING id"
    ).bind(spent_on.isoformat(), category, description, amount, str(data.get("method", ""))[:60],
        int(bool(data.get("recurring"))), str(data.get("notes", ""))[:500], user["id"]))
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'created','expense',?)").bind(user["id"], saved["id"]).run()
    return JSONResponse({"id": saved["id"]}, status_code=201)


@app.post("/api/expenses/delete")
async def delete_expense(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        expense_id = int(data.get("id", 0))
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the expense deletion")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose an expense"}, status_code=400)
    db = _env(request).DB
    expense = await _first(db.prepare("SELECT id FROM expenses WHERE id=?").bind(expense_id))
    if not expense:
        return JSONResponse({"error": "Expense not found"}, status_code=404)
    await db.prepare("DELETE FROM expenses WHERE id=?").bind(expense_id).run()
    await db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'deleted','expense',?)").bind(user["id"], expense_id).run()
    return {"ok": True}


@app.get("/api/settings")
async def settings(request: Request):
    _, error = await _require_user(request, ("owner",))
    if error:
        return error
    rows = await _env(request).DB.prepare("SELECT key,value FROM settings").all()
    result = dict(BUSINESS_SETTING_DEFAULTS)
    allowed = set(BUSINESS_SETTING_DEFAULTS) | {"invoice_logo_data", "invoice_logo_customized", "next_invoice_number"}
    result.update({r["key"]: r["value"] for r in _rows(rows) if r["key"] in allowed})
    return result


@app.post("/api/settings")
async def update_business_settings(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        values = {key: str(value).strip()[:500] for key, value in data.items() if key in BUSINESS_SETTING_DEFAULTS and key != "followup_reminder_lead_days"}
        for key, value in values.items():
            if key == "business_name" and (not value or len(value) > 120):
                raise ValueError("Business name must be 1–120 characters")
            if key == "business_email" and value and ("@" not in value or any(ch.isspace() for ch in value)):
                raise ValueError("Enter a valid business email")
            if key == "business_website" and value and (" " in value or "." not in value):
                raise ValueError("Enter a valid website address")
            if key == "invoice_prefix" and (not value or len(value) > 12 or not value.replace("-", "").isalnum()):
                raise ValueError("Invoice prefix may use letters, numbers and hyphens (up to 12 characters)")
            if key == "currency" and (len(value) != 3 or not value.isalpha()):
                raise ValueError("Currency must be a three-letter code")
            if key == "invoice_template_style" and value not in ("studio", "classic"):
                raise ValueError("Choose Studio or Classic invoice style")
            if key == "invoice_accent_color" and (len(value) != 7 or not value.startswith("#") or any(ch not in "0123456789abcdefABCDEF" for ch in value[1:])):
                raise ValueError("Choose a valid six-digit accent colour")
            if key in ("invoice_show_phone", "invoice_show_email", "invoice_show_website", "invoice_show_tax_id", "invoice_auto_installment_enabled"):
                values[key] = "1" if _boolean(value) else "0"
            if key == "invoice_auto_lead_days":
                days = int(value)
                if days < 0 or days > 365:
                    raise ValueError("Invoice lead time must be from zero to 365 days")
            if key in ("invoice_location",):
                values[key] = value[:100]
            if key == "invoice_footer_text":
                values[key] = value[:240]
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the business settings"}, status_code=400)
    db = _env(request).DB
    statements = [db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value) for key, value in values.items()]
    statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity) VALUES(?,'updated','business_settings')").bind(user["id"]))
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Settings were not saved; retry the update"}, status_code=409)
    return {"ok": True}


def _invoice_template(settings_map):
    style = settings_map.get("invoice_template_style", "studio")
    if style not in ("studio", "classic"):
        style = "studio"
    color = settings_map.get("invoice_accent_color", "#e51b2b")
    if len(color) != 7 or not color.startswith("#") or any(ch not in "0123456789abcdefABCDEF" for ch in color[1:]):
        color = "#e51b2b"
    return {"style": style, "accent_color": color, "location": settings_map.get("invoice_location", "")[:100],
            "footer_text": settings_map.get("invoice_footer_text", BUSINESS_SETTING_DEFAULTS["invoice_footer_text"])[:240],
            "show_phone": settings_map.get("invoice_show_phone", "1") == "1",
            "show_email": settings_map.get("invoice_show_email", "1") == "1",
            "show_website": settings_map.get("invoice_show_website", "1") == "1",
            "show_tax_id": settings_map.get("invoice_show_tax_id", "0") == "1"}


@app.get("/api/invoice/template")
async def invoice_template(request: Request):
    _, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    rows = await _env(request).DB.prepare("SELECT key,value FROM settings WHERE key LIKE 'invoice_%'").all()
    settings_map = dict(BUSINESS_SETTING_DEFAULTS)
    settings_map.update({r["key"]: r["value"] for r in _rows(rows)})
    return _invoice_template(settings_map)


@app.post("/api/invoice/template")
async def update_invoice_template(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        values = {}
        allowed = {"invoice_template_style", "invoice_accent_color", "invoice_location", "invoice_footer_text", "invoice_show_phone", "invoice_show_email", "invoice_show_website", "invoice_show_tax_id"}
        for key, raw in data.items():
            if key not in allowed:
                continue
            value = str(raw).strip()[:500]
            if key == "invoice_template_style" and value not in ("studio", "classic"):
                raise ValueError("Choose Studio or Classic invoice style")
            if key == "invoice_accent_color" and (len(value) != 7 or not value.startswith("#") or any(ch not in "0123456789abcdefABCDEF" for ch in value[1:])):
                raise ValueError("Choose a valid six-digit accent colour")
            if key == "invoice_location":
                value = value[:100]
            if key == "invoice_footer_text":
                value = value[:240]
            if key in ("invoice_show_phone", "invoice_show_email", "invoice_show_website", "invoice_show_tax_id"):
                value = "1" if _boolean(raw) else "0"
            values[key] = value
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the invoice template"}, status_code=400)
    db = _env(request).DB
    statements = [db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value) for key, value in values.items()]
    statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity) VALUES(?,'updated','invoice_template')").bind(user["id"]))
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Invoice template was not saved; retry the update"}, status_code=409)
    rows = await db.prepare("SELECT key,value FROM settings WHERE key LIKE 'invoice_%'").all()
    settings_map = dict(BUSINESS_SETTING_DEFAULTS)
    settings_map.update({r["key"]: r["value"] for r in _rows(rows)})
    return {"ok": True, "template": _invoice_template(settings_map)}


async def _reminder_stages(db):
    raw = await _setting(db, "emi_reminder_stages", "")
    try:
        data = json.loads(raw) if raw else {}
        stages = data.get("stages", REMINDER_STAGE_DEFAULTS)
        normalized = [{"offset_days": int(item["offset_days"]), "label": str(item.get("label", "Reminder"))[:60],
                       "subject": str(item.get("subject", "Payment reminder · {order_no}"))[:180],
                       "body": str(item.get("body", "Please review your scheduled payment."))[:2000]} for item in stages]
        repeat_days, repeat_after = int(data.get("repeat_days", 0)), int(data.get("repeat_after", 10))
        if not normalized or len(normalized) > 20 or any(not -365 <= x["offset_days"] <= 3650 for x in normalized):
            raise ValueError
        if len({x["offset_days"] for x in normalized}) != len(normalized) or not 0 <= repeat_days <= 365 or not 1 <= repeat_after <= 3650:
            raise ValueError
        return {"stages": sorted(normalized, key=lambda x: x["offset_days"]), "repeat_days": repeat_days, "repeat_after": repeat_after}
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"stages": REMINDER_STAGE_DEFAULTS, "repeat_days": 0, "repeat_after": 10}


async def _reminder_types(db):
    raw = await _setting(db, "emi_reminder_types", "")
    try:
        values = json.loads(raw) if raw else list(REMINDER_INSTALLMENT_TYPES)
        selected = list(dict.fromkeys(str(value) for value in values if str(value) in REMINDER_INSTALLMENT_TYPES))
        return selected or list(REMINDER_INSTALLMENT_TYPES)
    except (ValueError, TypeError, json.JSONDecodeError):
        return list(REMINDER_INSTALLMENT_TYPES)


@app.get("/api/followup/settings")
async def followup_settings(request: Request):
    _, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    verified = False  # No outbound email sender is configured in this Worker yet.
    channels = {name: await _setting(db, "email_" + name + "_enabled", "0") == "1" for name in ("payment", "invoice", "followup", "team")}
    try:
        lead_days = int(await _setting(db, "followup_reminder_lead_days", "5"))
    except ValueError:
        lead_days = 5
    return {"reminder_lead_days": lead_days, "sender_connected": verified, "sender_status": "not_connected",
        "email_channels": channels, "email_automation_enabled": False,
        "email_reminder_time": await _setting(db, "email_reminder_time", "09:00")}


@app.get("/api/settings/reminders")
async def reminder_settings(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    db = _env(request).DB
    count_rows = await db.prepare("SELECT status,COUNT(*) n FROM email_outbox GROUP BY status").all()
    recent_rows = await db.prepare("SELECT id,category,recipient,subject,scheduled_at,status,attempts,last_error,sent_at FROM email_outbox ORDER BY id DESC LIMIT 30").all() if user["role"] == "owner" else await db.prepare(
        "SELECT e.id,e.category,e.recipient,e.subject,e.scheduled_at,e.status,e.attempts,e.last_error,e.sent_at FROM email_outbox e "
        "WHERE e.installment_id IN (SELECT i.id FROM installments i JOIN orders o ON o.id=i.order_id WHERE o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team)) "
        "OR (e.dedupe_key LIKE 'invoice-send:%' AND CAST(substr(e.dedupe_key,14,instr(substr(e.dedupe_key,14),':')-1) AS INTEGER) IN "
        "(SELECT i.id FROM invoices i JOIN orders o ON o.id=i.order_id WHERE o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team))) "
        "ORDER BY e.id DESC LIMIT 30"
    ).bind(user["id"], user["id"]).all()
    counts = {row["status"]: int(row["n"]) for row in _rows(count_rows)}
    recent = []
    for row in _rows(recent_rows):
        local, _, domain = str(row["recipient"] or "").partition("@")
        recent.append({"id": row["id"], "category": row["category"], "recipient": local[:1] + "•••@" + domain if domain else "Invalid address",
            "subject": row["subject"], "scheduled_at": row["scheduled_at"], "status": row["status"], "attempts": row["attempts"],
            "last_error": row["last_error"], "sent_at": row["sent_at"]})
    channels = {f"email_{name}_enabled": await _setting(db, f"email_{name}_enabled", "0") == "1" for name in ("payment", "invoice", "followup", "team")}
    try:
        lead_days = int(await _setting(db, "invoice_auto_lead_days", "5"))
    except ValueError:
        lead_days = 5
    return {"enabled": any(channels.values()), "channels": channels, "emi_types": await _reminder_types(db),
        "send_time": await _setting(db, "email_reminder_time", "09:00"), "sender_verified": False,
        "daily_limit": 20, "counts": counts, "recent": recent, "emi_plan": await _reminder_stages(db),
        "invoice_auto_enabled": await _setting(db, "invoice_auto_installment_enabled", "1") == "1",
        "invoice_auto_lead_days": lead_days}


@app.post("/api/settings/reminders")
async def update_reminder_settings(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        db = _env(request).DB
        flags = {key: "1" if _boolean(data.get(key)) else "0" for key in ("email_payment_enabled", "email_invoice_enabled", "email_followup_enabled", "email_team_enabled")}
        if any(value == "1" for value in flags.values()):
            raise ValueError("Email delivery is not connected yet; save the reminder plan with email channels switched off")
        send_time = str(data.get("send_time", "09:00")).strip()
        if len(send_time) != 5 or send_time[2] != ":" or not send_time[:2].isdigit() or not send_time[3:].isdigit() or int(send_time[:2]) > 23 or int(send_time[3:]) > 59:
            raise ValueError("Choose a valid daily send time")
        types = data.get("emi_types")
        types_json = None
        if types is not None:
            if not isinstance(types, list):
                raise ValueError("Choose which payment types can receive reminders")
            selected = list(dict.fromkeys(str(x) for x in types))
            if not selected or any(x not in REMINDER_INSTALLMENT_TYPES for x in selected):
                raise ValueError("Select at least one valid payment type")
            types_json = json.dumps(selected)
        auto_enabled = data.get("invoice_auto_enabled")
        if auto_enabled is not None and not isinstance(auto_enabled, bool):
            raise ValueError("Choose whether installment invoice drafts should be created automatically")
        lead_days = data.get("invoice_auto_lead_days")
        if lead_days is not None:
            lead_days = int(lead_days)
            if not 1 <= lead_days <= 90:
                raise ValueError("Invoice draft lead time must be between 1 and 90 days")
        plan_json = None
        plan = data.get("emi_plan")
        if plan is not None:
            stages = plan.get("stages") if isinstance(plan, dict) else None
            if not isinstance(stages, list) or not 1 <= len(stages) <= 20:
                raise ValueError("Add between 1 and 20 reminder stages")
            normalized, offsets = [], set()
            for stage in stages:
                offset = int(stage.get("offset_days"))
                label, subject, body = str(stage.get("label", "")).strip()[:60], str(stage.get("subject", "")).strip()[:180], str(stage.get("body", "")).strip()[:2000]
                if not -365 <= offset <= 3650 or offset in offsets or not label or not subject or not body:
                    raise ValueError("Each reminder stage needs a unique valid day offset, name, subject and message")
                offsets.add(offset)
                normalized.append({"offset_days": offset, "label": label, "subject": subject, "body": body})
            repeat_days, repeat_after = int(plan.get("repeat_days", 0)), int(plan.get("repeat_after", 10))
            if not 0 <= repeat_days <= 365 or not 1 <= repeat_after <= 3650 or (repeat_days and not any(x["offset_days"] > 0 for x in normalized)):
                raise ValueError("Check the overdue reminder repeat settings")
            plan_json = json.dumps({"stages": sorted(normalized, key=lambda x: x["offset_days"]), "repeat_days": repeat_days, "repeat_after": repeat_after})
    except (ValueError, TypeError, AttributeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the reminder settings"}, status_code=400)
    statements = [db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value) for key, value in flags.items()]
    statements.append(db.prepare("INSERT INTO settings(key,value) VALUES('email_reminder_time',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(send_time))
    if auto_enabled is not None:
        statements.append(db.prepare("INSERT INTO settings(key,value) VALUES('invoice_auto_installment_enabled',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("1" if auto_enabled else "0"))
    if lead_days is not None:
        statements.append(db.prepare("INSERT INTO settings(key,value) VALUES('invoice_auto_lead_days',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(str(lead_days)))
    if plan_json is not None:
        statements.append(db.prepare("INSERT INTO settings(key,value) VALUES('emi_reminder_stages',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(plan_json))
    if types_json is not None:
        statements.append(db.prepare("INSERT INTO settings(key,value) VALUES('emi_reminder_types',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(types_json))
    statements.append(db.prepare("INSERT INTO audit_log(a…2963 tokens truncated…post("/api/incentive/team-rules")
async def update_incentive_team_rule(request: Request):
    user, error = await _require_user(request, ("manager",))
    if error:
        return error
    try:
        data = await request.json()
        employee_id = int(data.get("employee_id", 0))
        rep, manager = Decimal(str(data.get("rep_rate"))), Decimal(str(data.get("manager_rate")))
        if not rep.is_finite() or not manager.is_finite() or min(rep, manager) < 0 or max(rep, manager) > 100 or rep + manager > 100:
            raise ValueError("Employee and manager shares must total no more than 100%")
    except (ValueError, TypeError, InvalidOperation) as exc:
        return JSONResponse({"error": str(exc) or "Enter valid incentive shares"}, status_code=400)
    db = _env(request).DB
    employee = await _first(db.prepare("SELECT id FROM users WHERE id=? AND manager_id=? AND role='employee' AND is_active=1").bind(employee_id, user["id"]))
    if not employee:
        return JSONResponse({"error": "Choose an active direct report"}, status_code=403)
    try:
        await db.prepare("INSERT INTO manager_incentive_rules(employee_id,manager_id,rep_rate,manager_rate) VALUES(?,?,?,?) ON CONFLICT(employee_id) DO UPDATE SET manager_id=excluded.manager_id,rep_rate=excluded.rep_rate,manager_rate=excluded.manager_rate,updated_at=CURRENT_TIMESTAMP").bind(employee_id, user["id"], float(rep), float(manager)).run()
        await _audit(db, user["id"], "updated", "manager_incentive_rule", employee_id)
    except Exception:
        return JSONResponse({"error": "The incentive rule was not saved; retry"}, status_code=409)
    return {"ok": True}


async def _commission_scope(db, user):
    if user["role"] == "owner":
        return None
    if user["role"] == "employee":
        return [user["id"]]
    rows = await db.prepare("WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team").bind(user["id"]).all()
    return [row["id"] for row in _rows(rows)]


@app.get("/api/commissions")
async def commissions(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = await _commission_scope(db, user)
    clause, binds = ("", []) if scope is None else (f" AND e.employee_id IN ({','.join('?' for _ in scope) or 'NULL'})", scope)
    rows = _rows(await db.prepare(
        "SELECT e.*,u.name employee_name,s.name seller_name,o.order_no,o.customer_id,c.name customer,p.paid_on "
        "FROM commission_events e JOIN users u ON u.id=e.employee_id LEFT JOIN users s ON s.id=e.credited_employee_id "
        "JOIN orders o ON o.id=e.order_id JOIN users sale_owner ON sale_owner.id=o.employee_id "
        "JOIN customers c ON c.id=o.customer_id JOIN payments p ON p.id=e.payment_id "
        "WHERE sale_owner.role!='owner'" + clause + " ORDER BY COALESCE(e.due_date,p.paid_on) DESC,e.id DESC"
    ).bind(*binds).all())
    offsets, balances = {}, {}
    for row in rows:
        if int(row["amount_minor"]) < 0:
            offsets[row["employee_id"]] = offsets.get(row["employee_id"], 0) + abs(int(row["amount_minor"]))
        else:
            balances[row["id"]] = max(0, int(row["amount_minor"]) - int(row["paid_minor"]))
    for row in sorted((r for r in rows if int(r["amount_minor"]) > 0), key=lambda r: (r["due_date"] or "9999-12-31", r["id"])):
        uid, available = row["employee_id"], offsets.get(row["employee_id"], 0)
        applied = min(balances[row["id"]], available)
        balances[row["id"]] -= applied
        offsets[uid] = available - applied
    result = []
    for row in rows:
        amount = int(row["amount_minor"])
        balance = balances.get(row["id"], 0) if amount >= 0 else -min(abs(amount), offsets.get(row["employee_id"], 0))
        if amount < 0:
            offsets[row["employee_id"]] = max(0, offsets.get(row["employee_id"], 0) - abs(balance))
        entry = {"id": row["id"], "status": row["status"], "amount": _money(amount), "paid": _money(row["paid_minor"]),
            "balance": _money(balance), "rate": round(float(row["rate"] or 0), 4), "earned_on": row["paid_on"], "date": row["paid_on"],
            "due_date": row["due_date"], "paid_at": row["paid_at"], "employee_id": row["employee_id"],
            "employee": row["employee_name"], "beneficiary_role": row["beneficiary_role"] or "seller",
            "manager_level": row["manager_level"] or 0, "credited_employee_id": row["credited_employee_id"],
            "credited_employee": row["seller_name"] or row["employee_name"], "order_id": row["order_id"],
            "order_no": row["order_no"], "customer_id": row["customer_id"], "customer": row["customer"]}
        if user["role"] != "manager":
            entry["base"] = _money(row["base_minor"] or 0)
        result.append(entry)
    return result


@app.get("/api/commissions/payouts")
async def commission_payouts(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    scope = await _commission_scope(db, user)
    clause, binds = ("", []) if scope is None else (f" AND p.employee_id IN ({','.join('?' for _ in scope) or 'NULL'})", scope)
    rows = await db.prepare("SELECT p.*,u.name payee,actor.name recorded_by,COUNT(a.id) allocations FROM commission_payouts p JOIN users u ON u.id=p.employee_id LEFT JOIN users actor ON actor.id=p.created_by LEFT JOIN commission_payout_allocations a ON a.payout_id=p.id WHERE 1=1" + clause + " GROUP BY p.id ORDER BY p.paid_on DESC,p.id DESC").bind(*binds).all()
    return [{"id": r["id"], "employee_id": r["employee_id"], "employee": r["payee"], "amount": _money(r["amount_minor"]),
        "paid_on": r["paid_on"], "method": r["method"], "reference": r["reference"], "notes": r["notes"],
        "recorded_by": r["recorded_by"], "allocations": r["allocations"]} for r in _rows(rows)]


@app.post("/api/commissions/payout")
async def pay_commission(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        uid = int(data.get("user_id", 0))
        amount = _minor(data.get("amount"))
        paid_on = date.fromisoformat(str(data.get("paid_on") or date.today().isoformat())).isoformat()
        if paid_on > date.today().isoformat():
            raise ValueError("A payout cannot be marked paid in the future")
        if amount <= 0:
            raise ValueError("Enter a payout amount greater than zero")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the payout details"}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id FROM users WHERE id=? AND role IN ('manager','employee') AND is_active=1").bind(uid))
    if not person:
        return JSONResponse({"error": "Choose an active team member"}, status_code=400)
    events = _rows(await db.prepare("SELECT e.id,e.amount_minor,e.paid_minor,e.due_date FROM commission_events e JOIN orders o ON o.id=e.order_id JOIN users seller ON seller.id=o.employee_id AND seller.role!='owner' WHERE e.employee_id=? AND e.status='pending' AND e.amount_minor>e.paid_minor ORDER BY e.due_date,e.id").bind(uid).all())
    refunds = await _first(db.prepare("SELECT COALESCE(SUM(-amount_minor),0) n FROM commission_events WHERE employee_id=? AND amount_minor<0").bind(uid))
    recovery = int(refunds["n"] or 0)
    eligible = []
    for event in events:
        open_amount = int(event["amount_minor"]) - int(event["paid_minor"])
        offset = min(open_amount, recovery)
        open_amount -= offset
        recovery -= offset
        if open_amount:
            eligible.append((event, open_amount))
    available = sum(amount for _, amount in eligible)
    if amount > available:
        return JSONResponse({"error": "Payout exceeds the employee’s net payable incentive"}, status_code=400)
    method = str(data.get("method") or "Bank transfer").strip()[:80] or "Bank transfer"
    reference = str(data.get("reference", "")).strip()[:120] or None
    notes = str(data.get("notes", "")).strip()[:500] or None
    # Build the payout and all ledger allocations in one D1 batch. A concurrent
    # payout may choose the same candidate ID; the unique constraint safely
    # rejects one transaction rather than leaving an unallocated payout row.
    next_id = await _first(db.prepare("SELECT COALESCE(MAX(id),0)+1 id FROM commission_payouts"))
    payout_id = int(next_id["id"])
    statements = [db.prepare("INSERT INTO commission_payouts(id,employee_id,amount_minor,paid_on,method,reference,notes,created_by) VALUES(?,?,?,?,?,?,?,?)").bind(payout_id, uid, amount, paid_on, method, reference, notes, user["id"])]
    remaining = amount
    for event, available_event in eligible:
        if not remaining:
            break
        applied = min(remaining, available_event)
        new_paid = int(event["paid_minor"]) + applied
        state = "paid" if new_paid >= int(event["amount_minor"]) else "pending"
        statements.append(db.prepare("UPDATE commission_events SET paid_minor=?,status=?,paid_at=? WHERE id=?").bind(new_paid, state, paid_on, event["id"]))
        statements.append(db.prepare("INSERT INTO commission_payout_allocations(payout_id,commission_event_id,amount_minor) VALUES(?,?,?)").bind(payout_id, event["id"], applied))
        remaining -= applied
    statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'paid','incentive_payout',?)").bind(user["id"], payout_id))
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Payout allocation failed; refresh before trying again"}, status_code=409)
    return {"ok": True, "payout_id": payout_id}


@app.post("/api/commissions/due-date")
async def commission_due_date(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        event_id = int(data.get("event_id", 0))
        due_date = date.fromisoformat(str(data.get("due_date", ""))).isoformat()
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose an incentive and valid due date"}, status_code=400)
    db = _env(request).DB
    row = await _first(db.prepare("SELECT id,amount_minor,paid_minor,status FROM commission_events WHERE id=?").bind(event_id))
    if not row or row["status"] != "pending" or int(row["amount_minor"]) <= int(row["paid_minor"]):
        return JSONResponse({"error": "Only an unpaid incentive can be rescheduled"}, status_code=400)
    await db.prepare("UPDATE commission_events SET due_date=? WHERE id=?").bind(due_date, event_id).run()
    await _audit(db, user["id"], "rescheduled", "incentive", event_id)
    return {"ok": True, "due_date": due_date}


async def _target_user_scope(db, user):
    if user["role"] == "owner":
        return await db.prepare("SELECT id,name,email,role,manager_id FROM users WHERE role IN ('manager','employee') AND is_active=1 ORDER BY CASE role WHEN 'manager' THEN 0 ELSE 1 END,name").all()
    return await db.prepare("WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT u.id,u.name,u.email,u.role,u.manager_id FROM users u JOIN team t ON t.id=u.id WHERE u.role IN ('manager','employee') AND u.is_active=1 ORDER BY CASE u.role WHEN 'manager' THEN 0 ELSE 1 END,u.name").bind(user["id"]).all()


async def _target_plan_for_person(db, person, month):
    start = date.fromisoformat(month + "-01")
    end = date.fromisoformat((date(start.year + (start.month == 12), 1 if start.month == 12 else start.month + 1, 1)).isoformat())
    saved = await _first(db.prepare("SELECT conversion_target,assigned_by FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person["id"], month))
    target = int(saved["conversion_target"] or 0) if saved else 0
    actual_end = min(end, date.today() + timedelta(days=1)) if start <= date.today() else start
    actual = await _first(db.prepare("SELECT COUNT(*) n FROM orders WHERE employee_id=? AND status='active' AND order_date>=? AND order_date<?").bind(person["id"], start.isoformat(), actual_end.isoformat()))
    course_rows = await db.prepare("SELECT t.product_id,t.conversion_target,t.unit_price_minor,t.commission_rate,p.name,p.currency FROM target_course_targets t JOIN products p ON p.id=t.product_id WHERE t.user_id=? AND t.month_period=? ORDER BY p.name").bind(person["id"], month).all()
    course_targets = []
    today = date.today()
    rates = {
        "pool": float(await _setting(db, "incentive_pool_rate", "5")),
        "rep": float(await _setting(db, "incentive_rep_rate", "2")),
        "manager": float(await _setting(db, "incentive_manager_rate", "3")),
    }
    for course in _rows(course_rows):
        product_id = course["product_id"]
        sales = await _first(db.prepare("SELECT COALESCE(SUM(oi.quantity),0) n FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.employee_id=? AND o.status='active' AND oi.product_id=? AND o.order_date>=? AND o.order_date<?").bind(person["id"], product_id, start.isoformat(), actual_end.isoformat()))
        reports = await db.prepare("SELECT id,student_name,converted_on,notes FROM target_conversion_reports WHERE user_id=? AND product_id=? AND converted_on>=? AND converted_on<? ORDER BY converted_on,id").bind(person["id"], product_id, start.isoformat(), actual_end.isoformat()).all()
        sales_count = int(sales["n"] or 0)
        # Check-ins matched by student/date are not counted twice.
        unmatched = []
        for report in _rows(reports):
            match = await _first(db.prepare("SELECT 1 ok FROM orders o JOIN customers c ON c.id=o.customer_id JOIN order_items oi ON oi.order_id=o.id WHERE o.employee_id=? AND oi.product_id=? AND o.status='active' AND o.order_date=? AND lower(trim(c.name))=lower(trim(?)) LIMIT 1").bind(person["id"], product_id, report["converted_on"], report["student_name"]))
            report["matched_to_sale"] = bool(match)
            if not match:
                unmatched.append(report)
        completed = sales_count + len(unmatched)
        goal = int(course["conversion_target"] or 0)
        price = int(course["unit_price_minor"] or 0)
        rate = float(course["commission_rate"] or 0)
        seller_rate = rate if person["role"] == "manager" else min(rates["rep"], rate)
        manager_rate = 0 if person["role"] == "manager" else min(rates["manager"], max(0, rate - seller_rate))
        first_week, cursor, course_carry, course_weeks = start - timedelta(days=start.weekday()), start - timedelta(days=start.weekday()), 0, []
        while cursor < end:
            week_end = cursor + timedelta(days=7)
            allocation = await _first(db.prepare("SELECT conversion_target FROM target_course_week_allocations WHERE user_id=? AND month_period=? AND week_start=? AND product_id=?").bind(person["id"], month, cursor.isoformat(), product_id))
            weekly_sales = await _first(db.prepare("SELECT COALESCE(SUM(oi.quantity),0) n FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.employee_id=? AND o.status='active' AND oi.product_id=? AND o.order_date>=? AND o.order_date<?").bind(person["id"], product_id, max(start, cursor).isoformat(), min(end, week_end, today + timedelta(days=1)).isoformat()))
            weekly_reported = sum(1 for report in unmatched if max(start, cursor).isoformat() <= report["converted_on"] < min(end, week_end).isoformat())
            completed_week = int(weekly_sales["n"] or 0) + weekly_reported
            base = int(allocation["conversion_target"] or 0) if allocation else 0
            goal_week = base + course_carry
            remaining_week = max(0, goal_week - completed_week)
            status_week = "completed" if goal_week and remaining_week == 0 else "overdue" if week_end <= today and remaining_week else "current" if cursor <= today < week_end and goal_week else "upcoming" if goal_week else "no_goal"
            course_weeks.append({"week_start": cursor.isoformat(), "week_end": (week_end - timedelta(days=1)).isoformat(), "base_target": base, "carry_in": course_carry, "target": goal_week, "completed": completed_week, "remaining": remaining_week, "status": status_week})
            if week_end <= today:
                course_carry = remaining_week
            cursor = week_end
        course_current = next((week for week in course_weeks if week["week_start"] <= today.isoformat() <= week["week_end"]), None)
        course_targets.append({"product_id": product_id, "name": course["name"], "currency": course["currency"],
            "target": goal, "unit_price": price / 100, "estimated_income": goal * price / 100,
            "actual_income_estimate": completed * price / 100, "completed": completed,
            "sales_completed": sales_count, "reported_completed": len(unmatched),
            "remaining": max(0, goal - completed), "percent": round(min(100, completed / goal * 100), 1) if goal else 0,
            "commission_rate": rate, "estimated_incentive": round(goal * price * seller_rate / 100) / 100,
            "earned_incentive_estimate": round(completed * price * seller_rate / 100) / 100,
            "manager_share_estimate": round(goal * price * manager_rate / 100) / 100,
            "current_week": course_current, "weeks": course_weeks, "reports": unmatched})
    if course_targets:
        target = sum(c["target"] for c in course_targets)
        completed_count = sum(c["completed"] for c in course_targets)
    else:
        completed_count = int(actual["n"] or 0)
    month_end = end
    cursor = start - timedelta(days=start.weekday())
    today = date.today()
    weekly = []
    carry = 0
    current_week = today - timedelta(days=today.weekday())
    while cursor < month_end:
        week_end = cursor + timedelta(days=7)
        allocation = await _first(db.prepare("SELECT conversion_target FROM target_week_allocations WHERE user_id=? AND month_period=? AND week_start=?").bind(person["id"], month, cursor.isoformat()))
        override = await _first(db.prepare("SELECT conversion_target FROM targets WHERE user_id=? AND period=? AND period_type='weekly'").bind(person["id"], cursor.isoformat()))
        base = int(override["conversion_target"] if override else (allocation["conversion_target"] if allocation else 0))
        actual_week = await _first(db.prepare("SELECT COUNT(*) n FROM orders WHERE employee_id=? AND status='active' AND order_date>=? AND order_date<?").bind(person["id"], max(start, cursor).isoformat(), min(month_end, week_end, today + timedelta(days=1)).isoformat()))
        done = int(actual_week["n"] or 0)
        weekly_goal = base + carry
        remaining = max(0, weekly_goal - done)
        status = "completed" if weekly_goal and remaining == 0 else "overdue" if week_end <= today and remaining else "current" if cursor <= today < week_end and weekly_goal else "upcoming" if weekly_goal else "no_goal"
        weekly.append({"week_start": cursor.isoformat(), "week_end": (week_end - timedelta(days=1)).isoformat(), "base_target": base, "carry_in": carry, "target": weekly_goal, "completed": done, "remaining": remaining, "status": status, "manual": bool(override)})
        if cursor <= current_week < week_end:
            carry_current = carry
            current_week_data = weekly[-1]
        if week_end <= today:
            carry = remaining
        cursor = week_end
    if not weekly:
        carry_current, current_week_data = 0, {"target": 0, "completed": 0, "remaining": 0}
    else:
        current_week_data = next((w for w in weekly if w["week_start"] <= today.isoformat() <= w["week_end"]), weekly[0])
        carry_current = current_week_data["carry_in"]
    if course_targets:
        week_map = {}
        for course in course_targets:
            for item in course["weeks"]:
                entry = week_map.setdefault(item["week_start"], {"week_start": item["week_start"], "week_end": item["week_end"], "base_target": 0, "carry_in": 0, "target": 0, "completed": 0, "remaining": 0, "status": item["status"], "manual": False})
                for key in ("base_target", "carry_in", "target", "completed", "remaining"):
                    entry[key] += item[key]
                if item["status"] == "overdue": entry["status"] = "overdue"
                elif item["status"] == "current" and entry["status"] != "overdue": entry["status"] = "current"
        weekly = list(week_map.values())
        current_week_data = next((w for w in weekly if w["week_start"] <= today.isoformat() <= w["week_end"]), weekly[0] if weekly else {"target": 0, "completed": 0, "remaining": 0, "carry_in": 0})
        carry_current = current_week_data["carry_in"]
    price_goal = sum(c["estimated_income"] for c in course_targets) if course_targets else 0
    own_incentive = sum(c["estimated_incentive"] for c in course_targets) if course_targets else 0
    team_share = sum(c["manager_share_estimate"] for c in course_targets) if course_targets else 0
    return {"id": person["id"], "name": person["name"], "email": person["email"], "role": person["role"], "manager_id": person["manager_id"],
        "monthly_target": target, "assigned_by": saved["assigned_by"] if saved else None, "monthly_completed": completed_count,
        "monthly_remaining": max(0, target - completed_count), "monthly_percent": round(min(100, completed_count / target * 100), 1) if target else 0,
        "current_week_target": current_week_data["target"], "current_week_completed": current_week_data["completed"],
        "current_week_remaining": current_week_data["remaining"], "carry_forward": carry_current, "weeks": weekly,
        "course_targets": course_targets, "estimated_income": price_goal, "actual_income_estimate": sum(c["actual_income_estimate"] for c in course_targets),
        "estimated_own_incentive": own_incentive, "estimated_manager_share": team_share,
        "estimated_team_incentive": 0, "estimated_total_incentive": own_incentive + team_share}


@app.get("/api/targets")
async def targets(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    month = _month_key(request.query_params.get("month"))
    db = _env(request).DB
    people = _rows(await _target_user_scope(db, user))
    plans = [await _target_plan_for_person(db, person, month) for person in people]
    by_id = {plan["id"]: plan for plan in plans}
    for manager in (plan for plan in plans if plan["role"] == "manager"):
        descendants, frontier = set(), [manager["id"]]
        while frontier:
            parent = frontier.pop()
            for child in plans:
                if child["manager_id"] == parent and child["id"] not in descendants:
                    descendants.add(child["id"])
                    frontier.append(child["id"])
        manager["team_conversion_target"] = sum(by_id[uid]["monthly_target"] for uid in descendants)
        manager["estimated_team_incentive"] = round(sum(by_id[uid]["estimated_manager_share"] for uid in descendants if by_id[uid]["role"] == "employee"), 2)
        manager["estimated_total_incentive"] = round(manager["estimated_own_incentive"] + manager["estimated_team_incentive"], 2)
    rates = {"pool_rate": float(await _setting(db, "incentive_pool_rate", "5")), "rep_rate": float(await _setting(db, "incentive_rep_rate", "2")), "manager_rate": float(await _setting(db, "incentive_manager_rate", "3"))}
    if user["role"] == "manager":
        for plan in plans:
            for key in ("estimated_income", "actual_income_estimate"):
                plan.pop(key, None)
            for course in plan["course_targets"]:
                for key in ("unit_price", "estimated_income", "actual_income_estimate", "sales_completed"):
                    course.pop(key, None)
    manager_plan = next((p for p in plans if p["id"] == user["id"]), {})
    total_goal = sum(p["monthly_target"] for p in plans)
    total_done = sum(p["monthly_completed"] for p in plans)
    summary = {"assigned": sum(bool(p["monthly_target"]) for p in plans), "team_size": len(plans), "monthly_goal": total_goal,
        "monthly_completed": total_done, "monthly_remaining": max(0, total_goal - total_done),
        "carry_forward_due": sum(p["carry_forward"] for p in plans), "on_track": sum(bool(p["monthly_target"]) and not p["monthly_remaining"] for p in plans),
        "needs_attention": sum(bool(p["carry_forward"]) for p in plans)}
    forecast = {"available": any(p["course_targets"] for p in plans), "rep_rate": rates["rep_rate"], "manager_rate": rates["manager_rate"]}
    if user["role"] == "owner":
        summary.update({"estimated_income": round(sum(p["estimated_income"] for p in plans), 2),
            "actual_income_estimate": round(sum(p["actual_income_estimate"] for p in plans), 2),
            "estimated_incentive": round(sum(p["estimated_own_incentive"] + p["estimated_manager_share"] for p in plans), 2)})
        forecast.update({"pool_rate": rates["pool_rate"], "available": forecast["available"]})
    else:
        summary["estimated_incentive"] = round(manager_plan.get("estimated_total_incentive", 0), 2)
    return {"month": month, "current_month": month == date.today().strftime("%Y-%m"), "forecast": forecast,
        "summary": summary, "team": plans}


@app.get("/api/targets/self")
async def targets_self(request: Request):
    user, error = await _require_user(request, ("manager", "employee"))
    if error:
        return error
    month = _month_key(request.query_params.get("month"))
    db = _env(request).DB
    row = await _first(db.prepare("SELECT id,name,email,role,manager_id FROM users WHERE id=?").bind(user["id"]))
    plan = await _target_plan_for_person(db, row, month)
    assigned_by = await _first(db.prepare("SELECT assigned_by FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(user["id"], month))
    assigner = await _first(db.prepare("SELECT id,name,role FROM users WHERE id=?").bind(assigned_by["assigned_by"])) if assigned_by and assigned_by["assigned_by"] else None
    if user["role"] == "manager":
        for course in plan["course_targets"]:
            for key in ("unit_price", "estimated_income", "actual_income_estimate", "sales_completed"):
                course.pop(key, None)
    elif user["role"] == "employee":
        for course in plan["course_targets"]:
            for key in ("unit_price", "estimated_income", "actual_income_estimate", "sales_completed", "manager_share_estimate"):
                course.pop(key, None)
    return {"month": month, "person": {"id": row["id"], "name": row["name"], "role": row["role"]},
        "assigned_by": assigned_by["assigned_by"] if assigned_by else None,
        "assigned_by_name": assigner["name"] if assigner else None, "assigned_by_role": assigner["role"] if assigner else None,
        "courses": plan["course_targets"]}


@app.post("/api/targets")
async def save_target(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        person_id = int(data.get("user_id", 0))
        kind = str(data.get("period_type", "monthly"))
        if kind not in ("weekly", "monthly"):
            raise ValueError("Choose a weekly or monthly target")
        period_date = date.fromisoformat(str(data.get("period") or date.today().isoformat())[:10] if kind == "weekly" else str(data.get("period") or date.today().strftime("%Y-%m"))[:7] + "-01")
        period = (period_date - timedelta(days=period_date.weekday())).isoformat() if kind == "weekly" else period_date.strftime("%Y-%m")
        target = await _first(_env(request).DB.prepare("SELECT id,role,manager_id,name,email FROM users WHERE id=? AND role IN ('manager','employee') AND is_active=1").bind(person_id))
        if not target:
            raise ValueError("Active team member not found")
        db = _env(request).DB
        existing = await _first(db.prepare("SELECT conversion_target,assigned_by FROM targets WHERE user_id=? AND period=? AND period_type=?").bind(person_id, period, kind))
        if user["role"] == "manager":
            if target["role"] != "employee" or target["manager_id"] != user["id"]:
                return JSONResponse({"error": "Managers can assign targets only to their direct reports"}, status_code=403)
            if existing and existing["assigned_by"] != user["id"]:
                return JSONResponse({"error": "This owner-assigned target is read-only for managers"}, status_code=403)
        course_targets = data.get("course_targets")
        normalized = []
        if kind == "monthly" and isinstance(course_targets, list):
            if len(course_targets) > 12:
                raise ValueError("A monthly target can include up to 12 courses")
            seen = set()
            for item in course_targets:
                product_id, count = int(item.get("product_id", 0)), int(item.get("conversion_target", 0))
                if product_id in seen or count < 0 or count > 100000:
                    raise ValueError("Each course must have one valid conversion target")
                product = await _first(db.prepare("SELECT id,price_minor,commission_rate FROM products WHERE id=? AND product_type='course' AND active=1").bind(product_id))
                if not product:
                    raise ValueError("Choose an active course")
                seen.add(product_id)
                normalized.append((product_id, count, product["price_minor"], product["commission_rate"]))
        goal = sum(item[1] for item in normalized) if normalized else int(data.get("conversion_target", 0))
        if goal < 0 or goal > 100000:
            raise ValueError("Enter a conversion target from 0 to 100,000")
    except (ValueError, TypeError, AttributeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the target details"}, status_code=400)
    try:
        statements = [db.prepare("INSERT INTO targets(user_id,period,conversion_target,period_type,assigned_by) VALUES(?,?,?,?,?) ON CONFLICT(user_id,period) DO UPDATE SET conversion_target=excluded.conversion_target,period_type=excluded.period_type,assigned_by=excluded.assigned_by").bind(person_id, period, goal, kind, user["id"])]
        if kind == "monthly":
            statements.extend([
                db.prepare("DELETE FROM target_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, period),
                db.prepare("DELETE FROM target_course_targets WHERE user_id=? AND month_period=?").bind(person_id, period),
                db.prepare("DELETE FROM target_course_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, period),
            ])
            if normalized:
                statements.extend([db.prepare("INSERT INTO target_course_targets(user_id,month_period,product_id,conversion_target,unit_price_minor,commission_rate) VALUES(?,?,?,?,?,?)").bind(person_id, period, *row) for row in normalized])
            month_start = date.fromisoformat(period + "-01")
            month_end = date(month_start.year + (month_start.month == 12), 1 if month_start.month == 12 else month_start.month + 1, 1)
            weeks, week = [], month_start - timedelta(days=month_start.weekday())
            while week < month_end:
                weeks.append(week)
                week += timedelta(days=7)
            today = date.today()
            allocation_weeks = [w for w in weeks if period > today.strftime("%Y-%m") or w >= today - timedelta(days=today.weekday())]
            if allocation_weeks and not normalized:
                actual_month = await _first(db.prepare("SELECT COUNT(*) n FROM orders WHERE employee_id=? AND status='active' AND order_date>=? AND order_date<?").bind(person_id, month_start.isoformat(), min(month_end, today + timedelta(days=1)).isoformat()))
                remainder_goal = max(0, goal - int(actual_month["n"] or 0)) if period == today.strftime("%Y-%m") else goal
                base, extra = divmod(remainder_goal, len(allocation_weeks))
                statements.extend([db.prepare("INSERT INTO target_week_allocations(user_id,month_period,week_start,conversion_target) VALUES(?,?,?,?) ON CONFLICT(user_id,month_period,week_start) DO UPDATE SET conversion_target=excluded.conversion_target").bind(person_id, period, w.isoformat(), base + (1 if ix < extra else 0)) for ix, w in enumerate(allocation_weeks)])
            if allocation_weeks and normalized:
                allocations = []
                for product_id, course_goal, _, _ in normalized:
                    remaining_goal = course_goal
                    if period == today.strftime("%Y-%m"):
                        actual_course = await _first(db.prepare("SELECT COALESCE(SUM(oi.quantity),0) n FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.employee_id=? AND o.status='active' AND oi.product_id=? AND o.order_date>=? AND o.order_date<?").bind(person_id, product_id, month_start.isoformat(), min(month_end, today + timedelta(days=1)).isoformat()))
                        remaining_goal = max(0, course_goal - int(actual_course["n"] or 0))
                    base, extra = divmod(remaining_goal, len(allocation_weeks))
                    for ix, week in enumerate(allocation_weeks):
                        amount = base + (1 if ix < extra else 0)
                        allocations.append(db.prepare("INSERT INTO target_course_week_allocations(user_id,month_period,week_start,product_id,conversion_target) VALUES(?,?,?,?,?)").bind(person_id, period, week.isoformat(), product_id, amount))
                statements.extend(allocations)
        changed = not existing or int(existing["conversion_target"] or 0) != goal or int(existing["assigned_by"] or 0) != user["id"]
        statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','target',?)").bind(user["id"], person_id))
        if changed:
            summary = ", ".join(f"{row[1]} × course {row[0]}" for row in normalized)
            text = f"{user['name']} assigned you a {kind} goal of {goal} conversions ({period})."
            if summary:
                text += " Course targets: " + summary
            statements.append(db.prepare("INSERT INTO team_messages(sender_id,recipient_id,title,body) VALUES(?,?,?,?)").bind(user["id"], person_id, "Target updated" if existing else "New target assigned", text))
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "The target was not saved completely; retry after refreshing"}, status_code=409)
    return {"ok": True, "notification_sent": changed}


@app.post("/api/targets/report")
async def report_target_conversion(request: Request):
    user, error = await _require_user(request, ("manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        product_id = int(data.get("product_id", 0))
        converted = date.fromisoformat(str(data.get("converted_on") or date.today().isoformat()))
        student = str(data.get("student_name", "")).strip()[:120]
        if not student or converted > date.today():
            raise ValueError("Enter a student name and a date that is not in the future")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the conversion details"}, status_code=400)
    db = _env(request).DB
    month = converted.strftime("%Y-%m")
    product = await _first(db.prepare("SELECT id FROM products WHERE id=? AND product_type='course' AND active=1").bind(product_id))
    assigned = await _first(db.prepare("SELECT conversion_target FROM target_course_targets WHERE user_id=? AND month_period=? AND product_id=?").bind(user["id"], month, product_id))
    if not product or not assigned:
        return JSONResponse({"error": "This course is not included in your target for that month"}, status_code=400)
    duplicate = await _first(db.prepare("SELECT id FROM target_conversion_reports WHERE user_id=? AND product_id=? AND lower(trim(student_name))=lower(trim(?)) AND converted_on=?").bind(user["id"], product_id, student, converted.isoformat()))
    if duplicate:
        return JSONResponse({"error": "This conversion is already logged for that course and date"}, status_code=409)
    week = converted - timedelta(days=converted.weekday())
    await db.prepare("INSERT INTO target_conversion_reports(user_id,month_period,week_start,product_id,student_name,converted_on,notes,reported_by) VALUES(?,?,?,?,?,?,?,?)").bind(user["id"], month, week.isoformat(), product_id, student, converted.isoformat(), str(data.get("notes", "")).strip()[:500], user["id"]).run()
    await _audit(db, user["id"], "reported_conversion", "target_course", product_id)
    return {"ok": True}


async def _batch_assignment_statements(db, user, assignments, *, order_id=None, customer_id=None):
    if not isinstance(assignments, list) or not assignments or len(assignments) > 100:
        raise ValueError("Choose one or more course batch changes")
    checked, seen, pending_links = [], set(), {}
    for assignment in assignments:
        item_id = int(assignment.get("order_item_id", 0))
        if item_id in seen:
            raise ValueError("A course was included more than once")
        seen.add(item_id)
        where = "oi.id=? AND o.status='active'"
        binds = [item_id]
        if order_id is not None:
            where += " AND o.id=?"; binds.append(order_id)
        if customer_id is not None:
            where += " AND o.customer_id=?"; binds.append(customer_id)
        if user["role"] == "manager":
            where += " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team)"
            binds.append(user["id"])
        item = await _first(db.prepare("SELECT oi.id,oi.order_id,oi.product_id,oi.batch_id,p.product_type,p.active,o.customer_id FROM order_items oi JOIN products p ON p.id=oi.product_id JOIN orders o ON o.id=oi.order_id WHERE " + where).bind(*binds))
        if not item or item["product_type"] != "course":
            raise ValueError("That course is not part of this visible record")
        raw_batch = assignment.get("batch_id")
        batch_id = int(raw_batch) if raw_batch not in (None, "") else None
        if batch_id is not None:
            batch = await _first(db.prepare("SELECT id,product_id,status FROM batches WHERE id=?").bind(batch_id))
            if not batch or batch["status"] not in ("active", "setup_needed") or batch["product_id"] not in (None, item["product_id"]):
                raise ValueError("Choose an active batch for the same course")
            if batch["product_id"] is None:
                if batch_id in pending_links and pending_links[batch_id] != item["product_id"]:
                    raise ValueError("A batch can only be assigned to one course")
                pending_links[batch_id] = item["product_id"]
        checked.append((item["id"], item["batch_id"], batch_id, item["product_id"], bool(item["active"])))
    statements, changed = [], 0
    for item_id, old_batch, new_batch, product_id, product_active in checked:
        if old_batch == new_batch:
            continue
        if new_batch is not None:
            statements.append(db.prepare("UPDATE batches SET product_id=?,status=? WHERE id=? AND product_id IS NULL").bind(product_id, "active" if product_active else "setup_needed", new_batch))
        statements.append(db.prepare("UPDATE order_items SET batch_id=? WHERE id=?").bind(new_batch, item_id))
        statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,?, 'order_item',?)").bind(user["id"], "assigned" if old_batch is None else "reassigned", item_id))
        changed += 1
    return statements, changed


@app.post("/api/orders/batches")
async def update_order_batches(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        order_id = int(data.get("order_id", 0))
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose an order"}, status_code=400)
    db = _env(request).DB
    order = await _first(db.prepare("SELECT id FROM orders WHERE id=? AND status='active'").bind(order_id))
    if not order:
        return JSONResponse({"error": "Order not found"}, status_code=404)
    try:
        statements, changed = await _batch_assignment_statements(db, user, data.get("assignments"), order_id=order_id)
        if statements:
            await db.batch(statements)
    except (ValueError, TypeError, AttributeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the batch assignments"}, status_code=400)
    except Exception:
        return JSONResponse({"error": "The batch assignment was not saved; refresh and retry"}, status_code=409)
    return {"ok": True, "changed": changed}


@app.get("/api/customers/{customer_id}")
async def customer_profile(customer_id: int, request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    customer = await _first(db.prepare("SELECT id,name,phone,email,created_at FROM customers WHERE id=?").bind(customer_id))
    if not customer:
        return JSONResponse({"error": "Student not found"}, status_code=404)
    visible_orders = [row for row in await orders(request) if int(row["customer_id"]) == customer_id]
    if not visible_orders:
        return JSONResponse({"error": "Student not found in your workspace"}, status_code=404)
    order_ids = {int(row["id"]) for row in visible_orders}
    order_numbers = {row["order_no"] for row in visible_orders}
    visible_installments = [row for row in await installments(request) if row["order_no"] in order_numbers]
    visible_payments = [row for row in await payments(request) if int(row["order_id"]) in order_ids]
    if user["role"] == "employee":
        batch_rows = await db.prepare(
            "SELECT DISTINCT b.id,b.name,b.product_id,b.status FROM batches b JOIN order_items oi ON oi.batch_id=b.id "
            "JOIN orders o ON o.id=oi.order_id WHERE o.employee_id=? AND o.customer_id=? ORDER BY b.name"
        ).bind(user["id"], customer_id).all()
    else:
        batch_rows = await db.prepare("SELECT id,name,product_id,status FROM batches ORDER BY name").all()
    return {"student": {"id": customer["id"], "name": customer["name"], "phone": customer["phone"] or "",
                         "email": customer["email"] or "", "created_at": customer["created_at"]},
            "orders": visible_orders, "installments": visible_installments, "payments": visible_payments,
            "batches": [{"id": row["id"], "name": row["name"], "product_id": row["product_id"], "status": row["status"]} for row in _rows(batch_rows)]}


@app.post("/api/customers/update")
async def update_customer(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        customer_id = int(data.get("customer_id", 0))
        name = str(data.get("name", "")).strip()[:120]
        phone = str(data.get("phone", "")).strip()[:40]
        email = str(data.get("email", "")).strip()[:160]
        if not name:
            raise ValueError("Student name is required")
        if email and ("@" not in email or email.startswith("@") or email.endswith("@")):
            raise ValueError("Enter a valid email address")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the student details"}, status_code=400)
    db = _env(request).DB
    customer = await _first(db.prepare("SELECT id FROM customers WHERE id=?").bind(customer_id))
    if not customer:
        return JSONResponse({"error": "Student not found"}, status_code=404)
    try:
        statements, _ = await _batch_assignment_statements(db, user, data.get("assignments", []), customer_id=customer_id) if data.get("assignments") else ([], 0)
        statements.insert(0, db.prepare("UPDATE customers SET name=?,phone=?,email=? WHERE id=?").bind(name, phone, email, customer_id))
        statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','customer',?)").bind(user["id"], customer_id))
        await db.batch(statements)
    except (ValueError, TypeError, AttributeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the course changes"}, status_code=400)
    except Exception:
        return JSONResponse({"error": "Student details were not updated; refresh and retry"}, status_code=409)
    return {"ok": True}


@app.post("/api/targets/delete")
async def delete_target(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        person_id = int(data.get("user_id", 0))
        month = _month_key(data.get("month"))
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the target removal")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    db = _env(request).DB
    row = await _first(db.prepare("SELECT assigned_by FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person_id, month))
    if not row:
        return JSONResponse({"error": "There is no monthly target to remove for that month"}, status_code=404)
    if user["role"] == "manager":
        person = await _first(db.prepare("SELECT role,manager_id FROM users WHERE id=? AND is_active=1").bind(person_id))
        if not person or person["role"] != "employee" or person["manager_id"] != user["id"]:
            return JSONResponse({"error": "Managers can remove targets only for direct reports"}, status_code=403)
        if row["assigned_by"] != user["id"]:
            return JSONResponse({"error": "Only the owner can remove this owner-assigned target"}, status_code=403)
    await db.batch([
        db.prepare("DELETE FROM target_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, month),
        db.prepare("DELETE FROM target_course_targets WHERE user_id=? AND month_period=?").bind(person_id, month),
        db.prepare("DELETE FROM target_course_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, month),
        db.prepare("DELETE FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person_id, month),
        db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'deleted','monthly_target',?)").bind(user["id"], person_id)])
    return {"ok": True}


@app.post("/api/targets/reschedule")
async def reschedule_target(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        person_id = int(data.get("user_id", 0))
        source, destination = _month_key(data.get("from_month")), _month_key(data.get("to_month"))
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose valid target months"}, status_code=400)
    db = _env(request).DB
    current = await _first(db.prepare("SELECT conversion_target,assigned_by FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person_id, source))
    if not current:
        return JSONResponse({"error": "There is no monthly target to reschedule in that month"}, status_code=404)
    if user["role"] == "manager":
        person = await _first(db.prepare("SELECT role,manager_id FROM users WHERE id=? AND is_active=1").bind(person_id))
        if not person or person["role"] != "employee" or person["manager_id"] != user["id"]:
            return JSONResponse({"error": "Managers can only reschedule targets for direct reports"}, status_code=403)
        if current["assigned_by"] != user["id"]:
            return JSONResponse({"error": "Only the assigning manager can reschedule this target"}, status_code=403)
    if source != destination and await _first(db.prepare("SELECT 1 id FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person_id, destination)):
        return JSONResponse({"error": "A target already exists in the destination month"}, status_code=409)
    courses = data.get("course_targets")
    if courses is None:
        rows = await db.prepare("SELECT product_id,conversion_target FROM target_course_targets WHERE user_id=? AND month_period=?").bind(person_id, source).all()
        courses = [{"product_id": row["product_id"], "conversion_target": row["conversion_target"]} for row in _rows(rows)]
    try:
        normalized = []
        seen = set()
        if len(courses) > 12:
            raise ValueError("A monthly target can include up to 12 courses")
        for course in courses:
            product_id, goal = int(course.get("product_id", 0)), int(course.get("conversion_target", 0))
            if product_id in seen or goal < 0 or goal > 100000:
                raise ValueError("Each course must have one valid conversion target")
            product = await _first(db.prepare("SELECT id,price_minor,commission_rate FROM products WHERE id=? AND product_type='course' AND active=1").bind(product_id))
            if not product:
                raise ValueError("Choose an active course")
            seen.add(product_id)
            normalized.append((product_id, goal, product["price_minor"], product["commission_rate"]))
        goal = sum(c[1] for c in normalized) if normalized else int(data.get("conversion_target", current["conversion_target"]))
        if goal < 0 or goal > 100000:
            raise ValueError("Enter a conversion target from 0 to 100,000")
    except (ValueError, TypeError, AttributeError) as exc:
        return JSONResponse({"error": str(exc) or "Check the target details"}, status_code=400)
    statements = [db.prepare("INSERT INTO targets(user_id,period,conversion_target,period_type,assigned_by) VALUES(?,?,?,'monthly',?) ON CONFLICT(user_id,period) DO UPDATE SET conversion_target=excluded.conversion_target,period_type='monthly',assigned_by=excluded.assigned_by").bind(person_id, destination, goal, user["id"]),
        db.prepare("DELETE FROM target_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, destination),
        db.prepare("DELETE FROM target_course_targets WHERE user_id=? AND month_period=?").bind(person_id, destination),
        db.prepare("DELETE FROM target_course_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, destination)]
    statements += [db.prepare("INSERT INTO target_course_targets(user_id,month_period,product_id,conversion_target,unit_price_minor,commission_rate) VALUES(?,?,?,?,?,?)").bind(person_id, destination, *c) for c in normalized]
    month_start = date.fromisoformat(destination + "-01")
    month_end = date(month_start.year + (month_start.month == 12), 1 if month_start.month == 12 else month_start.month + 1, 1)
    today = date.today()
    weeks, cursor = [], month_start - timedelta(days=month_start.weekday())
    while cursor < month_end:
        weeks.append(cursor)
        cursor += timedelta(days=7)
    active_weeks = [week for week in weeks if destination > today.strftime("%Y-%m") or week >= today - timedelta(days=today.weekday())]
    if active_weeks and not normalized:
        actual = await _first(db.prepare("SELECT COUNT(*) n FROM orders WHERE employee_id=? AND status='active' AND order_date>=? AND order_date<?").bind(person_id, month_start.isoformat(), min(month_end, today + timedelta(days=1)).isoformat()))
        remaining_goal = max(0, goal - int(actual["n"] or 0)) if destination == today.strftime("%Y-%m") else goal
        base, extra = divmod(remaining_goal, len(active_weeks))
        statements.extend([db.prepare("INSERT INTO target_week_allocations(user_id,month_period,week_start,conversion_target) VALUES(?,?,?,?)").bind(person_id, destination, week.isoformat(), base + (1 if ix < extra else 0)) for ix, week in enumerate(active_weeks)])
    elif active_weeks:
        for product_id, course_goal, _, _ in normalized:
            remaining_goal = course_goal
            if destination == today.strftime("%Y-%m"):
                actual = await _first(db.prepare("SELECT COALESCE(SUM(oi.quantity),0) n FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE o.employee_id=? AND o.status='active' AND oi.product_id=? AND o.order_date>=? AND o.order_date<?").bind(person_id, product_id, month_start.isoformat(), min(month_end, today + timedelta(days=1)).isoformat()))
                remaining_goal = max(0, course_goal - int(actual["n"] or 0))
            base, extra = divmod(remaining_goal, len(active_weeks))
            statements.extend([db.prepare("INSERT INTO target_course_week_allocations(user_id,month_period,week_start,product_id,conversion_target) VALUES(?,?,?,?,?)").bind(person_id, destination, week.isoformat(), product_id, base + (1 if ix < extra else 0)) for ix, week in enumerate(active_weeks)])
    statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'rescheduled','monthly_target',?)").bind(user["id"], person_id))
    if source != destination:
        statements += [db.prepare("DELETE FROM target_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, source),
            db.prepare("DELETE FROM target_course_targets WHERE user_id=? AND month_period=?").bind(person_id, source),
            db.prepare("DELETE FROM target_course_week_allocations WHERE user_id=? AND month_period=?").bind(person_id, source),
            db.prepare("DELETE FROM targets WHERE user_id=? AND period=? AND period_type='monthly'").bind(person_id, source)]
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "The target month was not changed; retry after refreshing"}, status_code=409)
    return {"ok": True, "notification_sent": True}


@app.get("/api/dashboard")
async def dashboard(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    db = _env(request).DB
    if user["role"] != "owner":
        own = await _first(db.prepare(
            "SELECT COALESCE((SELECT SUM(e.amount_minor-e.paid_minor) FROM commission_events e WHERE e.employee_id=?),0) incentive_pending,"
            "COALESCE((SELECT SUM(e.paid_minor) FROM commission_events e WHERE e.employee_id=?),0) incentive_paid,"
            "(SELECT COUNT(*) FROM orders WHERE employee_id=? AND status='active') conversions"
        ).bind(user["id"], user["id"], user["id"]))
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
    totals = await _first(db.prepare(
        "SELECT COALESCE((SELECT SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END) FROM payments),0) received,"
        "COALESCE((SELECT SUM(total_minor) FROM orders WHERE status='active'),0) expected,"
        "COALESCE((SELECT SUM(amount_minor) FROM expenses),0) expenses,"
        "(SELECT COUNT(*) FROM orders WHERE status='active') conversions,"
        "COALESCE((SELECT SUM(amount_minor-paid_minor) FROM commission_events),0) incentive_pending,"
        "COALESCE((SELECT SUM(paid_minor) FROM commission_events),0) incentive_paid"
    ))
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
    for row in _rows(team):
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
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds = [user["id"]]
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
    for r in _rows(rows):
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


@app.post("/api/invoices")
async def create_invoice(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        order_id = int(data.get("order_id", 0))
    except (ValueError, TypeError):
        return JSONResponse({"error": "Choose a valid course or product order"}, status_code=400)
    db = _env(request).DB
    scope = ""
    binds = [order_id]
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT id FROM users WHERE manager_id=? AND is_active=1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team UNION SELECT ?)"
        binds.extend([user["id"], user["id"]])
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds.append(user["id"])
    if user["role"] == "employee":
        scope += " AND o.employee_id=?"
        binds.append(user["id"])
    order = await _first(db.prepare(
        "SELECT o.id,o.order_no,o.order_date,o.currency,o.subtotal_minor,o.discount_minor,o.tax_minor,o.total_minor,"
        "o.employee_id,c.name customer,c.phone,c.email FROM orders o JOIN customers c ON c.id=o.customer_id "
        "WHERE o.id=? AND o.status='active'" + scope
    ).bind(*binds))
    if not order:
        return JSONResponse({"error": "Order not found in your workspace"}, status_code=404)
    existing = await _first(db.prepare(
        "SELECT id FROM invoices WHERE order_id=? AND invoice_kind='order' AND installment_id IS NULL"
    ).bind(order_id))
    if existing:
        return JSONResponse({"error": "An invoice has already been created for this order"}, status_code=409)
    items_result = await db.prepare(
        "SELECT p.product_type,p.sku,p.name,COALESCE(b.name,'') batch_name,oi.quantity,oi.unit_price_minor,"
        "oi.discount_minor,oi.line_total_minor FROM order_items oi JOIN products p ON p.id=oi.product_id "
        "LEFT JOIN batches b ON b.id=oi.batch_id WHERE oi.order_id=? ORDER BY oi.id"
    ).bind(order_id).all()
    item_rows = _rows(items_result)
    if not item_rows:
        return JSONResponse({"error": "This order has no invoice items"}, status_code=400)
    settings_result = await db.prepare(
        "SELECT key,value FROM settings WHERE key IN ('invoice_prefix','next_invoice_number','business_name',"
        "'business_email','business_phone','business_website','business_address','business_tax_id','invoice_logo_data')"
    ).all()
    settings_map = {row["key"]: row["value"] for row in _rows(settings_result)}
    prefix = str(settings_map.get("invoice_prefix", "INV"))[:20]
    try:
        number = max(1, int(settings_map.get("next_invoice_number", "1001")))
    except (TypeError, ValueError):
        return JSONResponse({"error": "Invoice numbering needs an owner review in Settings"}, status_code=409)
    invoice_no = f"{prefix}-{number:05d}"
    statements = [db.prepare(
        "INSERT INTO invoices(order_id,invoice_no,issued_on,status,created_by) VALUES(?,?,?,'draft',?)"
    ).bind(order_id, invoice_no, date.today().isoformat(), user["id"])]
    statements.append(db.prepare(
        "INSERT INTO invoice_profiles(invoice_id,business_name,business_email,business_phone,business_website,"
        "business_address,business_tax_id,logo_data,customer_name,customer_phone,customer_email,currency,order_no,"
        "order_date,subtotal_minor,discount_minor,tax_minor,total_minor) "
        "SELECT id,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? FROM invoices WHERE invoice_no=?"
    ).bind(settings_map.get("business_name", "OFFTune Business Desk"), settings_map.get("business_email", ""),
        settings_map.get("business_phone", ""), settings_map.get("business_website", ""),
        settings_map.get("business_address", ""), settings_map.get("business_tax_id", ""),
        settings_map.get("invoice_logo_data", ""), order["customer"], order["phone"] or "", order["email"] or "",
        order["currency"], order["order_no"], order["order_date"], order["subtotal_minor"],
        order["discount_minor"], order["tax_minor"], order["total_minor"], invoice_no))
    for item in item_rows:
        statements.append(db.prepare(
            "INSERT INTO invoice_items(invoice_id,product_type,sku,description,batch_name,quantity,unit_price_minor,discount_minor,line_total_minor) "
            "SELECT id,?,?,?,?,?,?,?,? FROM invoices WHERE invoice_no=?"
        ).bind(item["product_type"], item["sku"], item["name"], item["batch_name"], item["quantity"],
            item["unit_price_minor"], item["discount_minor"], item["line_total_minor"], invoice_no))
    statements.extend([
        db.prepare("INSERT INTO settings(key,value) VALUES('next_invoice_number',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(str(number + 1)),
        db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) SELECT ?,'draft_created','invoice',id FROM invoices WHERE invoice_no=?").bind(user["id"], invoice_no),
    ])
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Invoice was not saved; no partial invoice changes were kept. Please retry."}, status_code=409)
    invoice = await _first(db.prepare("SELECT id FROM invoices WHERE invoice_no=?").bind(invoice_no))
    return JSONResponse({"id": invoice["id"], "invoice_no": invoice_no}, status_code=201)


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
    elif user["role"] == "employee":
        scope = " AND o.employee_id=?"
        binds.append(user["id"])
    row = await _first(db.prepare(
        "SELECT i.id,i.order_id,i.invoice_no,i.issued_on,i.status,i.invoice_kind,i.installment_id,"
        "o.order_no,o.order_date,o.currency,o.subtotal_minor,o.discount_minor,o.tax_minor,o.total_minor,"
        "c.name customer,c.phone,c.email,ip.business_name,ip.business_email,ip.business_phone,ip.business_website,"
        "ip.business_address,ip.business_tax_id,ip.logo_data,ip.customer_name,ip.customer_phone,ip.customer_email,"
        "ip.currency snap_currency,ip.order_no snap_order_no,ip.order_date snap_order_date,ip.subtotal_minor snap_subtotal_minor,"
        "ip.discount_minor snap_discount_minor,ip.tax_minor snap_tax_minor,ip.total_minor snap_total_minor,"
        "ip.installment_received_minor FROM invoices i JOIN orders o ON o.id=i.order_id "
        "JOIN customers c ON c.id=o.customer_id LEFT JOIN invoice_profiles ip ON ip.invoice_id=i.id "
        "WHERE i.id=?" + scope
    ).bind(*binds))
    if not row:
        return None, JSONResponse({"error": "Invoice not found"}, status_code=404)
    received_row = await _first(db.prepare(
        "SELECT COALESCE(SUM(amount_minor),0) n FROM payment_allocations WHERE installment_id=?"
    ).bind(row["installment_id"])) if row["installment_id"] else await _first(db.prepare(
        "SELECT COALESCE(SUM(CASE WHEN payment_type='receipt' THEN amount_minor ELSE -amount_minor END),0) n FROM payments WHERE order_id=?"
    ).bind(row["order_id"]))
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
    inst = await _first(db.prepare("SELECT installment_no,due_date FROM installments WHERE id=?").bind(row["installment_id"])) if row["installment_id"] else None
    sched_rows = await db.prepare(
        "SELECT i.installment_no,i.due_date,i.amount_minor,COALESCE(SUM(pa.amount_minor),0) received_minor "
        "FROM installments i LEFT JOIN payment_allocations pa ON pa.installment_id=i.id "
        "WHERE i.order_id=? GROUP BY i.id ORDER BY i.installment_no"
    ).bind(row["order_id"]).all()
    schedule = [{"installment_no": r["installment_no"], "due_date": r["due_date"],
        "amount": _money(r["amount_minor"]), "received": _money(r["received_minor"]),
        "balance": _money(max(0, int(r["amount_minor"] or 0) - int(r["received_minor"] or 0))),
        "status": "Paid" if int(r["amount_minor"] or 0) <= int(r["received_minor"] or 0) else "Part paid" if r["received_minor"] else "Unpaid"}
        for r in _rows(sched_rows)]
    if inst:
        schedule = [r for r in schedule if r["installment_no"] == inst["installment_no"]]
        for entry in schedule:
            entry.update({"amount": _money(total), "received": _money(min(total, max(0, received))),
                          "balance": _money(max(0, total - received)),
                          "status": "Paid" if total <= received else "Part paid" if received else "Unpaid"})
    settings_rows = await db.prepare("SELECT key,value FROM settings WHERE key IN ('business_name','business_email','business_phone','business_website','business_address','business_tax_id','invoice_logo_data')").all()
    cfg = {r["key"]: r["value"] for r in _rows(settings_rows)}
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
            "discount": _money(x["discount_minor"]), "line_total": _money(x["line_total_minor"])} for x in _rows(items_rows)],
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


@app.post("/api/invoices/delete")
async def delete_invoice(request: Request):
    user, error = await _require_user(request, ("owner", "manager"))
    if error:
        return error
    try:
        data = await request.json()
        invoice_id = int(data.get("invoice_id", 0))
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the invoice deletion")
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc) or "Choose an invoice"}, status_code=400)
    db = _env(request).DB
    scope = ""
    binds = [invoice_id]
    if user["role"] == "manager":
        scope = " AND o.employee_id IN (WITH RECURSIVE team(id) AS (SELECT ? UNION ALL SELECT u.id FROM users u JOIN team t ON u.manager_id=t.id WHERE u.is_active=1) SELECT id FROM team)"
        binds.append(user["id"])
    invoice = await _first(db.prepare("SELECT i.id,i.invoice_no FROM invoices i JOIN orders o ON o.id=i.order_id WHERE i.id=?" + scope).bind(*binds))
    if not invoice:
        return JSONResponse({"error": "Invoice not found"}, status_code=404)
    await db.batch([
        db.prepare("DELETE FROM invoice_items WHERE invoice_id=?").bind(invoice_id),
        db.prepare("DELETE FROM invoice_profiles WHERE invoice_id=?").bind(invoice_id),
        db.prepare("DELETE FROM invoices WHERE id=?").bind(invoice_id),
        db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'deleted','invoice',?)").bind(user["id"], invoice_id),
    ])
    return {"ok": True}


@app.post("/api/auth/setup")
async def auth_setup(request: Request):
    data = await request.json()
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    if not name or len(name) > 120 or "@" not in email or len(email) > 254:
        return JSONResponse({"error": "Enter a valid owner name and email"}, status_code=400)
    db = _env(request).DB
    count = await _first(db.prepare("SELECT COUNT(*) AS n FROM users"))
    if count["n"]:
        return JSONResponse({"error": "Workspace setup is already complete"}, status_code=409)
    try:
        password = _hash_password(str(data.get("password", "")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    result = _plain(await db.prepare(
        "INSERT INTO users(name,email,password_hash,role) "
        "SELECT ?,?,?,'owner' WHERE NOT EXISTS (SELECT 1 FROM users)"
    ).bind(name, email, password).run())
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
    user = await _first(db.prepare("SELECT id,password_hash,is_active FROM users WHERE lower(email)=?").bind(email))
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
        session = await _first(_env(request).DB.prepare(
            "SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?"
        ).bind(digest, int(time.time())))
        if session and not hmac.compare_digest(
            str(request.headers.get("x-csrf-token", "")), str(session["csrf"])
        ):
            return JSONResponse({"error": "Refresh the page and try again"}, status_code=403)
        if session:
            await _env(request).DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(digest).run()
    response = JSONResponse({"ok": True})
    response.delete_cookie("offtune_session", path="/", secure=True, httponly=True, samesite="strict")
    return response


def _validated_image_data(value, label="image"):
    image = str(value or "")
    if not image:
        return ""
    if len(image) > 700000:
        raise ValueError(f"{label.capitalize()} must be under 512 KB")
    header, sep, payload = image.partition(",")
    mime = header[5:].split(";", 1)[0] if sep and header.startswith("data:") else ""
    if mime not in ("image/png", "image/jpeg", "image/webp") or ";base64" not in header:
        raise ValueError("Choose a PNG, JPEG or WebP image")
    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("That image file could not be read")
    signatures = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8", "image/webp": b"RIFF"}
    if not raw or len(raw) > 512000 or not raw.startswith(signatures[mime]) or (mime == "image/webp" and raw[8:12] != b"WEBP"):
        raise ValueError(f"Choose a valid PNG, JPEG or WebP {label} under 512 KB")
    return image


@app.post("/api/auth/profile")
async def update_owner_profile(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        if not name or len(name) > 120 or "@" not in email or len(email) > 254 or any(ch.isspace() for ch in email):
            raise ValueError("Enter a valid owner name and email")
        current = await _first(_env(request).DB.prepare("SELECT password_hash FROM users WHERE id=? AND role='owner'").bind(user["id"]))
        if not current or not _password_matches(str(data.get("current_password", "")), str(current["password_hash"])):
            return JSONResponse({"error": "Current password is incorrect"}, status_code=401)
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    db = _env(request).DB
    duplicate = await _first(db.prepare("SELECT id FROM users WHERE lower(email)=? AND id<>?").bind(email, user["id"]))
    if duplicate:
        return JSONResponse({"error": "That email is already used by another account"}, status_code=409)
    try:
        await db.batch([
            db.prepare("UPDATE users SET name=?,email=? WHERE id=?").bind(name, email, user["id"]),
            db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','owner_profile',?)").bind(user["id"], user["id"]),
        ])
    except Exception:
        return JSONResponse({"error": "Owner profile was not saved"}, status_code=409)
    return {"ok": True, "user": {"id": user["id"], "name": name, "email": email, "role": "owner", "manager_id": None}}


@app.post("/api/auth/reset-password")
async def reset_owner_password(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        password = str(data.get("password", ""))
        if len(password) < 12:
            raise ValueError("Use a password with at least 12 characters")
        owner = await _first(_env(request).DB.prepare("SELECT password_hash FROM users WHERE id=? AND role='owner'").bind(user["id"]))
        if not owner or not _password_matches(str(data.get("current_password", "")), str(owner["password_hash"])):
            return JSONResponse({"error": "Current password is incorrect"}, status_code=401)
        new_hash = _hash_password(password)
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    cookie = request.cookies.get("offtune_session")
    if not cookie:
        return JSONResponse({"error": "Sign in again to reset your password"}, status_code=401)
    token_hash = hashlib.sha256(cookie.encode()).hexdigest()
    db = _env(request).DB
    try:
        await db.batch([
            db.prepare("UPDATE users SET password_hash=? WHERE id=?").bind(new_hash, user["id"]),
            db.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(user["id"], token_hash),
            db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'reset','password',?)").bind(user["id"], user["id"]),
        ])
    except Exception:
        return JSONResponse({"error": "Password was not changed; retry the update"}, status_code=409)
    return {"ok": True, "other_sessions_signed_out": True}


@app.post("/api/profile")
async def update_profile(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        name = str(data.get("name", "")).strip()
        if not name or len(name) > 120:
            raise ValueError("Enter a name up to 120 characters")
        image = _validated_image_data(data.get("data_url"), "profile photo")
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    db = _env(request).DB
    sql = "UPDATE users SET name=?,avatar_data=? WHERE id=?" if image else "UPDATE users SET name=? WHERE id=?"
    args = (name, image, user["id"]) if image else (name, user["id"])
    await db.batch([db.prepare(sql).bind(*args), db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','own_profile',?)").bind(user["id"], user["id"])])
    fresh = await _first(db.prepare("SELECT id,name,email,role,manager_id,job_title,designation_id,avatar_data FROM users WHERE id=?").bind(user["id"]))
    return {"ok": True, "user": fresh}


@app.post("/api/profile/avatar")
async def update_profile_avatar(request: Request):
    user, error = await _require_user(request, ("owner", "manager", "employee"))
    if error:
        return error
    try:
        data = await request.json()
        target = int(data.get("user_id") or user["id"])
        if target != user["id"] and user["role"] != "owner":
            return JSONResponse({"error": "You can update only your own profile photo"}, status_code=403)
        image = _validated_image_data(data.get("data_url"), "profile photo")
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    db = _env(request).DB
    person = await _first(db.prepare("SELECT id FROM users WHERE id=? AND is_active=1").bind(target))
    if not person:
        return JSONResponse({"error": "Account not found"}, status_code=404)
    await db.batch([db.prepare("UPDATE users SET avatar_data=? WHERE id=?").bind(image, target), db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'updated','profile_photo',?)").bind(user["id"], target)])
    return {"ok": True, "avatar_data": image, "user_id": target}


@app.post("/api/settings/logo")
async def update_business_logo(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        image = _validated_image_data(data.get("data_url"), "logo")
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    customized = "1" if image else "0"
    db = _env(request).DB
    try:
        await db.batch([
            db.prepare("INSERT INTO settings(key,value) VALUES('invoice_logo_data',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(image),
            db.prepare("INSERT INTO settings(key,value) VALUES('invoice_logo_customized',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(customized),
            db.prepare("INSERT INTO audit_log(actor_id,action,entity) VALUES(?,?, 'invoice_logo')").bind(user["id"], "updated" if image else "restored_default"),
        ])
    except Exception:
        return JSONResponse({"error": "Logo was not saved; retry the update"}, status_code=409)
    return {"ok": True, "has_logo": bool(image), "customized": bool(image)}


@app.post("/api/data/reset")
async def reset_workspace_data(request: Request):
    user, error = await _require_user(request, ("owner",))
    if error:
        return error
    try:
        data = await request.json()
        scope = str(data.get("scope", "records")).strip()
        if scope not in ("records", "workspace"):
            raise ValueError("Choose a valid reset scope")
        if data.get("confirmed") is not True:
            raise ValueError("Confirm the selected reset")
        if len(str(data.get("current_password", ""))) < 1:
            raise ValueError("Enter your current password to continue")
    except (TypeError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    db = _env(request).DB
    owner = await _first(db.prepare("SELECT password_hash FROM users WHERE id=? AND role='owner'").bind(user["id"]))
    if not owner or not _password_matches(str(data.get("current_password", "")), str(owner["password_hash"])):
        return JSONResponse({"error": "Current password is incorrect"}, status_code=401)
    open_link = await _first(db.prepare("SELECT id FROM razorpay_payment_links WHERE status IN ('created','partially_paid') LIMIT 1").bind())
    if open_link:
        return JSONResponse({"error": "Close or reconcile open online payment links before resetting student records"}, status_code=409)
    reset_tables = ["razorpay_webhook_events", "razorpay_payment_links", "commission_payout_allocations", "commission_payouts",
        "manager_incentive_rules", "commission_events", "target_conversion_reports", "invoices", "followup_logs",
        "payment_allocations", "payments", "installments", "order_items", "orders", "customers", "expenses"]
    statements = []
    if scope == "workspace":
        reset_tables = ["email_outbox"] + reset_tables + ["target_course_week_allocations", "target_course_targets", "target_week_allocations", "targets"]
    else:
        statements.append(db.prepare("DELETE FROM email_outbox WHERE installment_id IN (SELECT id FROM installments) OR dedupe_key LIKE 'invoice-send:%'"))
    statements.extend(db.prepare(f"DELETE FROM {table}") for table in reset_tables)
    if scope == "workspace":
        statements.extend([
            db.prepare("DELETE FROM team_messages"), db.prepare("DELETE FROM batches"), db.prepare("DELETE FROM products"),
            db.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role!='owner')"),
            db.prepare("UPDATE users SET manager_id=NULL WHERE id<>?").bind(user["id"]),
            db.prepare("DELETE FROM users WHERE id<>?").bind(user["id"]),
            db.prepare("DELETE FROM designations WHERE is_system=0"), db.prepare("DELETE FROM audit_log"), db.prepare("DELETE FROM settings"),
        ])
        defaults = {**BUSINESS_SETTING_DEFAULTS, "invoice_logo_data": "", "invoice_logo_customized": "0", "next_invoice_number": "1001"}
        statements.extend(db.prepare("INSERT INTO settings(key,value) VALUES(?,?)").bind(key, value) for key, value in defaults.items())
    statements.append(db.prepare("INSERT INTO audit_log(actor_id,action,entity) VALUES(?,?,?)").bind(user["id"], "factory_reset" if scope == "workspace" else "records_reset", scope))
    try:
        await db.batch(statements)
    except Exception:
        return JSONResponse({"error": "Reset was not completed; no partial reset was kept"}, status_code=409)
    return {"ok": True, "scope": scope}


@app.post("/api/team/preview")
async def preview_team_workspace(request: Request):
    owner, error = await _require_user(request, ("owner",))
    if error:
        return error
    cookie = request.cookies.get("offtune_session")
    token_hash = hashlib.sha256(cookie.encode()).hexdigest()
    db = _env(request).DB
    current = await _first(db.prepare("SELECT act_as_user_id FROM sessions WHERE token_hash=?").bind(token_hash))
    if not current or current["act_as_user_id"]:
        return JSONResponse({"error": "Return to the owner workspace before switching again"}, status_code=409)
    try:
        data = await request.json()
        target = int(data.get("user_id", 0))
    except (TypeError, ValueError):
        return JSONResponse({"error": "Choose an active team member"}, status_code=400)
    person = await _first(db.prepare("SELECT id FROM users WHERE id=? AND role IN ('manager','employee') AND is_active=1").bind(target))
    if not person:
        return JSONResponse({"error": "Choose an active manager or employee"}, status_code=400)
    await db.batch([db.prepare("UPDATE sessions SET act_as_user_id=? WHERE token_hash=?").bind(target, token_hash), db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'opened_workspace_preview','user',?)").bind(owner["id"], target)])
    return {"ok": True}


@app.post("/api/team/preview/end")
async def end_team_workspace_preview(request: Request):
    user, error = await _require_user(request, ("manager", "employee"))
    if error:
        return error
    cookie = request.cookies.get("offtune_session")
    token_hash = hashlib.sha256(cookie.encode()).hexdigest()
    db = _env(request).DB
    session = await _first(db.prepare("SELECT s.user_id owner_id,s.act_as_user_id,u.role owner_role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?").bind(token_hash))
    if not session or session["owner_role"] != "owner" or not session["act_as_user_id"]:
        return JSONResponse({"error": "You are already in the owner workspace"}, status_code=409)
    await db.batch([db.prepare("INSERT INTO audit_log(actor_id,action,entity,entity_id) VALUES(?,'returned_from_workspace_preview','user',?)").bind(session["owner_id"], session["act_as_user_id"]), db.prepare("UPDATE sessions SET act_as_user_id=NULL WHERE token_hash=?").bind(token_hash)])
    return {"ok": True}


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
