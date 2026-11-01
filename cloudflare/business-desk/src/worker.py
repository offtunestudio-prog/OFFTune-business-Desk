Warning: truncated output (original token count: 41474)
Total output lines: 2504

"""Cloudflare Worker entry point for OFFTune Business Desk."""

import hashlib
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
        "FROM sessions s JOIN users u ON u.id=s.user_id "
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
        "SELECT s.csrf,s.expires_at,u.id,u.name,u.email,u.role,u.manager_id,u.job_title,"
        "u.designation_id,u.avatar_data,d.name designation,d.permissions_json,d.data_permissions_json "
        "FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN designations d ON d.id=u.designation_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1"
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
            return JSONResponse({"error": "Choose an active manager"}, s…11474 tokens truncated…    course_weeks.append({"week_start": cursor.isoformat(), "week_end": (week_end - timedelta(days=1)).isoformat(), "base_target": base, "carry_in": course_carry, "target": goal_week, "completed": completed_week, "remaining": remaining_week, "status": status_week})
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
