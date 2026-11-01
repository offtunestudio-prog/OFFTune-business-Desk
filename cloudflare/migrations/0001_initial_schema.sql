-- Schema-only migration generated from the local OFFTune SQLite schema.
-- No local customer, student, credential, or business rows are included.
-- Review before applying to a hosted database.

CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
            entity TEXT NOT NULL, entity_id INTEGER, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE batches (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, product_id INTEGER REFERENCES products(id),
            start_date TEXT, end_date TEXT, status TEXT NOT NULL DEFAULT 'active'
        );

CREATE TABLE commission_events (
            id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id),
            payment_id INTEGER NOT NULL REFERENCES payments(id), employee_id INTEGER NOT NULL REFERENCES users(id),
            rate REAL NOT NULL, amount_minor INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','paid','reversed')),
            paid_minor INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, paid_at TEXT
        , credited_employee_id INTEGER REFERENCES users(id), beneficiary_role TEXT NOT NULL DEFAULT 'seller', manager_level INTEGER NOT NULL DEFAULT 0, base_minor INTEGER NOT NULL DEFAULT 0, due_date TEXT);

CREATE TABLE commission_payout_allocations (
            id INTEGER PRIMARY KEY, payout_id INTEGER NOT NULL REFERENCES commission_payouts(id) ON DELETE CASCADE,
            commission_event_id INTEGER NOT NULL REFERENCES commission_events(id),
            amount_minor INTEGER NOT NULL CHECK(amount_minor > 0)
        );

CREATE TABLE commission_payouts (
            id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES users(id),
            amount_minor INTEGER NOT NULL CHECK(amount_minor > 0), paid_on TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'Bank transfer', reference TEXT, notes TEXT,
            created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE customers (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT, email TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE designations (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            role_class TEXT NOT NULL CHECK(role_class IN ('manager','employee')),
            permissions_json TEXT NOT NULL, is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        , data_permissions_json TEXT NOT NULL DEFAULT '[]');

CREATE TABLE email_outbox (
            id INTEGER PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, category TEXT NOT NULL,
            recipient TEXT NOT NULL, subject TEXT NOT NULL, text_body TEXT NOT NULL, html_body TEXT NOT NULL DEFAULT '',
            scheduled_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued'
                CHECK(status IN ('queued','sending','sent','failed','skipped')),
            attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, sent_at TEXT
        , installment_id INTEGER REFERENCES installments(id) ON DELETE SET NULL);

CREATE TABLE expenses (
            id INTEGER PRIMARY KEY, spent_on TEXT NOT NULL, category TEXT NOT NULL,
            description TEXT NOT NULL, amount_minor INTEGER NOT NULL CHECK(amount_minor >= 0),
            method TEXT, recurring INTEGER NOT NULL DEFAULT 0, notes TEXT,
            created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE followup_logs (
            id INTEGER PRIMARY KEY, installment_id INTEGER NOT NULL REFERENCES installments(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id), outcome TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
            promised_date TEXT, next_followup_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE installments (
            id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
            installment_no INTEGER NOT NULL, due_date TEXT NOT NULL, amount_minor INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', promised_date TEXT, followup_outcome TEXT NOT NULL DEFAULT '', followup_at TEXT,
            UNIQUE(order_id, installment_no)
        );

CREATE TABLE invoice_items (
            id INTEGER PRIMARY KEY, invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
            product_type TEXT NOT NULL, sku TEXT NOT NULL DEFAULT '', description TEXT NOT NULL,
            batch_name TEXT NOT NULL DEFAULT '', quantity INTEGER NOT NULL,
            unit_price_minor INTEGER NOT NULL, discount_minor INTEGER NOT NULL,
            line_total_minor INTEGER NOT NULL
        );

CREATE TABLE invoice_profiles (
            invoice_id INTEGER PRIMARY KEY REFERENCES invoices(id) ON DELETE CASCADE,
            business_name TEXT NOT NULL, business_email TEXT NOT NULL DEFAULT '',
            business_phone TEXT NOT NULL DEFAULT '', business_website TEXT NOT NULL DEFAULT '',
            business_address TEXT NOT NULL DEFAULT '', business_tax_id TEXT NOT NULL DEFAULT '',
            logo_data TEXT NOT NULL DEFAULT '', customer_name TEXT NOT NULL,
            customer_phone TEXT NOT NULL DEFAULT '', customer_email TEXT NOT NULL DEFAULT '',
            currency TEXT NOT NULL, order_no TEXT NOT NULL, order_date TEXT NOT NULL,
            subtotal_minor INTEGER NOT NULL, discount_minor INTEGER NOT NULL,
            tax_minor INTEGER NOT NULL, total_minor INTEGER NOT NULL
        , installment_received_minor INTEGER NOT NULL DEFAULT 0);

CREATE TABLE invoices (
            id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id),
            invoice_no TEXT NOT NULL UNIQUE, issued_on TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'issued', created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        , installment_id INTEGER REFERENCES installments(id) ON DELETE SET NULL, invoice_kind TEXT NOT NULL DEFAULT 'order');

CREATE TABLE manager_incentive_rules (
            employee_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            manager_id INTEGER NOT NULL REFERENCES users(id),
            rep_rate REAL NOT NULL CHECK(rep_rate>=0 AND rep_rate<=100),
            manager_rate REAL NOT NULL CHECK(manager_rate>=0 AND manager_rate<=100),
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE order_items (
            id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
            product_id INTEGER NOT NULL REFERENCES products(id), batch_id INTEGER REFERENCES batches(id),
            quantity INTEGER NOT NULL CHECK(quantity > 0), unit_price_minor INTEGER NOT NULL,
            discount_minor INTEGER NOT NULL DEFAULT 0, line_total_minor INTEGER NOT NULL
        , commission_rate REAL NOT NULL DEFAULT 5);

CREATE TABLE orders (
            id INTEGER PRIMARY KEY, order_no TEXT NOT NULL UNIQUE, customer_id INTEGER NOT NULL REFERENCES customers(id),
            employee_id INTEGER REFERENCES users(id), order_date TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
            currency TEXT NOT NULL DEFAULT 'INR', subtotal_minor INTEGER NOT NULL,
            discount_minor INTEGER NOT NULL DEFAULT 0, tax_minor INTEGER NOT NULL DEFAULT 0,
            total_minor INTEGER NOT NULL, installment_count INTEGER NOT NULL DEFAULT 1,
            first_due_date TEXT, notes TEXT, created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        , admission_minor INTEGER NOT NULL DEFAULT 0, emi_due_day INTEGER NOT NULL DEFAULT 1, enrollment_status TEXT NOT NULL DEFAULT 'admitted', booking_minor INTEGER NOT NULL DEFAULT 0, course_start_date TEXT, admission_due_date TEXT, discount_label TEXT NOT NULL DEFAULT '');

CREATE TABLE payment_allocations (
            id INTEGER PRIMARY KEY, payment_id INTEGER NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
            installment_id INTEGER NOT NULL REFERENCES installments(id) ON DELETE CASCADE,
            amount_minor INTEGER NOT NULL CHECK(amount_minor != 0), UNIQUE(payment_id, installment_id)
        );

CREATE TABLE payments (
            id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES orders(id),
            payment_type TEXT NOT NULL CHECK(payment_type IN ('receipt','refund')),
            paid_on TEXT NOT NULL, amount_minor INTEGER NOT NULL CHECK(amount_minor > 0),
            method TEXT NOT NULL, reference TEXT, notes TEXT, created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE products (
            id INTEGER PRIMARY KEY, sku TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            product_type TEXT NOT NULL CHECK(product_type IN ('course','sample_pack','digital_product')),
            price_minor INTEGER NOT NULL CHECK(price_minor >= 0), currency TEXT NOT NULL DEFAULT 'INR',
            installment_allowed INTEGER NOT NULL DEFAULT 0, commission_rate REAL NOT NULL DEFAULT 5,
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE razorpay_payment_links (
            id INTEGER PRIMARY KEY, installment_id INTEGER NOT NULL REFERENCES installments(id) ON DELETE CASCADE,
            order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
            invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
            link_id TEXT NOT NULL UNIQUE, reference_id TEXT NOT NULL UNIQUE, short_url TEXT NOT NULL,
            currency TEXT NOT NULL, amount_minor INTEGER NOT NULL, amount_paid_minor INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'created', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE razorpay_receipts (
            payment_id TEXT PRIMARY KEY, payment_row_id INTEGER NOT NULL UNIQUE REFERENCES payments(id) ON DELETE CASCADE,
            payment_link_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE razorpay_webhook_events (
            id INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, event_type TEXT NOT NULL,
            raw_body BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
            attempts INTEGER NOT NULL DEFAULT 0, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT, last_error TEXT NOT NULL DEFAULT ''
        );

CREATE TABLE sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
        , act_as_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE target_conversion_reports (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            month_period TEXT NOT NULL, week_start TEXT NOT NULL,
            product_id INTEGER NOT NULL REFERENCES products(id), student_name TEXT NOT NULL,
            converted_on TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
            reported_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE target_course_targets (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            month_period TEXT NOT NULL, product_id INTEGER NOT NULL REFERENCES products(id),
            conversion_target INTEGER NOT NULL DEFAULT 0, unit_price_minor INTEGER NOT NULL DEFAULT 0,
            commission_rate REAL NOT NULL DEFAULT 0,
            PRIMARY KEY(user_id,month_period,product_id)
        );

CREATE TABLE target_course_week_allocations (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            month_period TEXT NOT NULL, week_start TEXT NOT NULL,
            product_id INTEGER NOT NULL REFERENCES products(id), conversion_target INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(user_id,month_period,week_start,product_id)
        );

CREATE TABLE target_week_allocations (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, month_period TEXT NOT NULL,
            week_start TEXT NOT NULL, conversion_target INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(user_id,month_period,week_start)
        );

CREATE TABLE targets (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), period TEXT NOT NULL,
            conversion_target INTEGER NOT NULL DEFAULT 0, period_type TEXT NOT NULL DEFAULT 'monthly', assigned_by INTEGER REFERENCES users(id), UNIQUE(user_id, period)
        );

CREATE TABLE team_messages (
            id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL,
            body TEXT NOT NULL, remind_at TEXT, read_at TEXT, completed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

CREATE TABLE users (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','manager','employee')),
            manager_id INTEGER REFERENCES users(id), is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        , job_title TEXT NOT NULL DEFAULT '', avatar_data TEXT NOT NULL DEFAULT '', designation_id INTEGER REFERENCES designations(id) ON DELETE SET NULL);

CREATE INDEX idx_commission_payout_employee_date ON commission_payouts(employee_id,paid_on);

CREATE INDEX idx_commissions_crediting_seller ON commission_events(credited_employee_id,status);

CREATE INDEX idx_commissions_due_date ON commission_events(due_date,status,employee_id);

CREATE INDEX idx_commissions_employee ON commission_events(employee_id, status);

CREATE INDEX idx_email_outbox_delivery ON email_outbox(status,scheduled_at,id);

CREATE INDEX idx_expenses_date ON expenses(spent_on);

CREATE UNIQUE INDEX idx_invoice_installment_unique ON invoices(installment_id) WHERE installment_id IS NOT NULL;

CREATE INDEX idx_orders_customer ON orders(customer_id);

CREATE INDEX idx_orders_employee_date ON orders(employee_id, order_date);

CREATE INDEX idx_payment_allocations_installment ON payment_allocations(installment_id);

CREATE INDEX idx_payments_order_date ON payments(order_id, paid_on);

CREATE INDEX idx_razorpay_link_installment ON razorpay_payment_links(installment_id,status);

CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE INDEX idx_target_week_allocations_user_week ON target_week_allocations(user_id,week_start);

CREATE INDEX idx_team_messages_recipient ON team_messages(recipient_id,completed_at,remind_at);
