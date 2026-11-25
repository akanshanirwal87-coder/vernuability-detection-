# Production Deployment Guide

This guide details best practices for deploying SecureCode AI into production environments.

---

## 1. Security Architecture & Hardening

1. **Unprivileged Containers**:
   - Backend and Celery workers run as UID `10001` (`appuser`).
   - Root filesystem permissions are restricted.
2. **SSRF & Network Isolation**:
   - Outbound repository ingestion enforces strict HTTPS, approved host whitelisting (`github.com`), and blocks private RFC 1918 / loopback IPs.
   - Internal database and Redis ports are not mapped to host interfaces in production (`docker-compose.prod.yml`).
3. **CORS & Reverse Proxy**:
   - Nginx terminates client connections and enforces security headers:
     - `X-Frame-Options: SAMEORIGIN`
     - `X-Content-Type-Options: nosniff`
     - `X-XSS-Protection: 1; mode=block`
     - `Referrer-Policy: strict-origin-when-cross-origin`
   - CORS in FastAPI is restricted to trusted origins via `CORS_ALLOWED_ORIGINS`.

---

## 2. Environment Configuration Reference

| Environment Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@db:5432/securecode` |
| `REDIS_URL` | Redis broker connection URL | `redis://redis:6379/0` |
| `CELERY_BROKER_URL` | Celery broker URL | `redis://redis:6379/0` |
| `CELERY_RESULT_BACKEND` | Celery result store | `redis://redis:6379/1` |
| `ENVIRONMENT` | Deployment environment | `production` |
| `JWT_SECRET_KEY` | Symmetric key for user tokens | `generate-random-32-byte-hex` |
| `GITHUB_APP_ID` | GitHub App numeric Identifier | `123456` |
| `GITHUB_APP_PRIVATE_KEY` | RS256 private key PEM | `-----BEGIN RSA PRIVATE KEY-----...` |
| `GITHUB_APP_CLIENT_ID` | GitHub App OAuth Client ID | `Iv1.xxxxxxxxxxxx` |
| `GITHUB_APP_CLIENT_SECRET` | GitHub App OAuth Client Secret | `secret-xxxx` |
| `GITHUB_WEBHOOK_SECRET` | Shared secret for HMAC validation | `random-webhook-secret` |
| `CORS_ALLOWED_ORIGINS` | Permitted frontend origins | `https://securecode.company.com` |

---

## 3. Deployment Checklist

- [ ] Ensure `JWT_SECRET_KEY` is rotated and not default.
- [ ] Configure `POSTGRES_PASSWORD` with a strong secret.
- [ ] Install SSL/TLS certificate on Nginx reverse proxy.
- [ ] Provision GitHub App private key in backend environment.
- [ ] Verify database migrations completed: `docker compose exec backend alembic upgrade head`.
- [ ] Verify live system health: `curl -f https://<domain>/health`.
