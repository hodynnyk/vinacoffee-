# VINA Coffee — production rollout

## Current status
The current Data Centre interface in `public/` is still a **localStorage prototype**, not production software. Do not enter real guest phone numbers or employee details until authentication and encrypted storage are implemented.

## Existing Cloudflare D1 connection
The existing database `vinacoffee-` is now configured in `wrangler.jsonc` with binding `DB`. Do not create a duplicate database. The binding alone does not apply schema migrations or prove successful deployment.

1. Review `migrations/0001_initial.sql` and make sure the existing database has no conflicting tables or important data. Take a backup if it has data.
2. From the project directory run `npm install`, then `npx wrangler d1 migrations apply vinacoffee- --remote`. This changes the **real** database, so inspect the migration first.
3. Deploy via the existing GitHub → Cloudflare pipeline, or run `npm run deploy` with appropriate credentials.
4. Open `/api/health`: `database: ready` indicates the Worker can query D1; `not_configured` means the binding is missing; `unavailable` means query failed.

## Security gates before real use
- Implement vetted password hashing, protected sessions, CSRF defense, owner MFA, backend role authorization and rate limits.
- Encrypt guest phone data with AES-256-GCM and use keyed HMAC blind indexes for exact lookup. Keep keys in Cloudflare secrets, never in repository or browser.
- Verify Telegram Mini App initData server-side and obtain consent for phone collection.
- Loyalty balance changes must be atomic, idempotent and auditable. Stock reports must not silently change numeric quantity.
- Only after these controls are tested should the browser-local demo be replaced with authenticated API-backed UI.

## Scope of initial migration
Employees, sessions, guests, loyalty accounts and transactions, shifts, stock items/reports/movements, audit events, task templates/completions, and events. This migration is a schema foundation, not a complete backend.
