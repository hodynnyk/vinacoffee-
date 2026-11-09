# VINA Coffee — production rollout

## Current status
The current Data Centre interface in `public/` is a **localStorage prototype**, not production software. Do not enter real guest phone numbers, employee details, or inventory data. No employee authentication is implemented yet.

## First infrastructure milestone: Cloudflare D1
1. In Cloudflare create a D1 database named `vinacoffee-db` (if it does not already exist).
2. Copy its actual `database_id` from Cloudflare (never guess it).
3. Add the following to `wrangler.jsonc` (preserving the existing worker and assets settings):

```json
"d1_databases": [
  { "binding": "DB", "database_name": "vinacoffee-db", "database_id": "<REAL_DATABASE_ID>", "migrations_dir": "migrations" }
]
```

4. Review `migrations/0001_initial.sql`, then apply: `npx wrangler d1 migrations apply vinacoffee-db --remote`.
5. Deploy using the existing GitHub→Cloudflare pipeline or `npm run deploy` after reviewing changes.
6. Check `/api/health`. `database: ready` means the Worker can query D1; `not_configured` means the binding is missing.

## Security gates before real use
- Implement Argon2id employee password hashing with a vetted Workers-compatible implementation, protected server sessions, CSRF defense, owner MFA, backend role authorization and rate limits.
- Use AES-256-GCM encryption for guest phone data and keyed HMAC blind indexes for exact lookup. Keep keys in Cloudflare secrets, never in repository or browser.
- Verify Telegram Mini App initData server-side and obtain consent for phone collection.
- Loyalty balance changes must be atomic, idempotent and auditable. Stock reports must not silently change numeric quantity.
- Only after these controls are tested should the browser-local demo be replaced with authenticated API-backed UI.

## Scope of initial migration
Employees, sessions, guests, loyalty accounts and transactions, shifts, stock items/reports/movements, audit events, task templates/completions, and events. This migration is a schema foundation, not a complete backend.
