# V2 Security Deployment Checklist

Do not deploy this security branch until the required Railway variables and
database migration below are ready. The app intentionally fails closed when
critical production security configuration is missing.

## Required before deployment

1. Generate a unique secret locally:

   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

2. Add the result to Railway as `SECRET_KEY`, then seal that variable.
3. Set `APP_BASE_URL` to the canonical HTTPS hub URL.
4. Set `TRUSTED_HOSTS` to the hostname only. Add comma-separated hostnames if
   both a Railway domain and custom domain must work.
5. Leave `ALLOWED_ORIGINS` unset while the UI and API share the same domain.
6. Apply `migrations/022_create_login_rate_limits.sql` to Railway Postgres.
7. When v2 is ready to replace v1, set Railway's Start Command to
   `./v2/start.sh`. Do not change the current command before migration and
   login testing are complete.

## Controls implemented

- No known or hardcoded production session secret
- HTTPS-only, HttpOnly, SameSite session cookie
- Eight-hour absolute session lifetime and 30-minute inactivity timeout
- Active-user and role revalidation on every authenticated request
- Restricted hostnames and fixed magic-link base URL
- Restrictive CORS default
- CSRF protection for login, reviewer actions, and admin actions
- Database-backed per-IP and per-email magic-link throttling
- Hashed, short-lived, one-time magic links with atomic consumption
- Previous unused magic links invalidated when a new one is requested
- HSTS, CSP, clickjacking, MIME-sniffing, referrer, and permissions headers
- No-store caching for authenticated and sensitive responses

## Remaining high-priority work

- Replace magic-link-only authentication with Microsoft Entra ID and enforced MFA
- Move inline scripts/styles into static assets and remove `unsafe-inline` from CSP
- Separate the web and email-worker processes into different Railway services
- Review and minimize Microsoft Graph/O365 application permissions
- Encrypt or minimize stored email bodies and define retention/deletion rules
- Add dependency vulnerability scanning, secret scanning, and automated tests in CI
- Configure database backups, restore testing, access alerts, and audit retention
- Arrange an independent penetration test before broad production use
