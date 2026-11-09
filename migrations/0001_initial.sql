-- VINA Coffee / initial production data model (Cloudflare D1)
-- Apply with: npx wrangler d1 migrations apply vinacoffee-db --remote
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS employees (
 id TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','manager','barista')),
 password_hash TEXT NOT NULL, rank TEXT NOT NULL DEFAULT 'start', active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS sessions (
 id_hash TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
 expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_employee ON sessions(employee_id);
CREATE TABLE IF NOT EXISTS guests (
 id TEXT PRIMARY KEY, telegram_id TEXT NOT NULL UNIQUE, phone_ciphertext TEXT,
 phone_lookup_hash TEXT UNIQUE, consent_at TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS loyalty_accounts (
 guest_id TEXT PRIMARY KEY REFERENCES guests(id), balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
 updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS loyalty_transactions (
 id TEXT PRIMARY KEY, guest_id TEXT NOT NULL REFERENCES guests(id), employee_id TEXT REFERENCES employees(id),
 delta INTEGER NOT NULL CHECK(delta <> 0), reason TEXT NOT NULL,
 idempotency_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_loyalty_guest ON loyalty_transactions(guest_id,created_at);
CREATE TABLE IF NOT EXISTS shifts (
 id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES employees(id), opened_at TEXT NOT NULL,
 closed_at TEXT, close_reason TEXT CHECK(close_reason IN ('manual','midnight','owner')),
 CHECK(closed_at IS NULL OR closed_at >= opened_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_shift ON shifts(employee_id) WHERE closed_at IS NULL;
CREATE TABLE IF NOT EXISTS stock_items (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, unit TEXT NOT NULL, quantity REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','low','out')),
 critical INTEGER NOT NULL DEFAULT 0 CHECK(critical IN (0,1)), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS stock_reports (
 id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES stock_items(id), employee_id TEXT NOT NULL REFERENCES employees(id),
 reported_status TEXT NOT NULL CHECK(reported_status IN ('low','out')), note TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS stock_movements (
 id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES stock_items(id), actor_id TEXT NOT NULL REFERENCES employees(id),
 delta REAL NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS audit_events (
 id TEXT PRIMARY KEY, actor_id TEXT REFERENCES employees(id), action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id TEXT, details_json TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
CREATE TABLE IF NOT EXISTS task_templates (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS task_completions (
 id TEXT PRIMARY KEY, template_id TEXT NOT NULL REFERENCES task_templates(id), employee_id TEXT NOT NULL REFERENCES employees(id),
 completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, starts_at TEXT NOT NULL, recurrence_rule TEXT,
 created_by TEXT NOT NULL REFERENCES employees(id)
);
