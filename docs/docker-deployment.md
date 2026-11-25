# Docker Containerization & Multi-Container Deployment

SecureCode AI is packaged as modular, multi-stage Docker containers for consistent development and production deployments.

---

## 1. Container Images

### 1.1 Backend Container (`Dockerfile.backend`)
- **Base**: `python:3.12-slim`
- **Multi-Stage Architecture**:
  - `builder`: Installs compilers (`gcc`, `libpq-dev`), builds virtual environment at `/opt/venv`.
  - `runner`: Copies minimal virtualenv, installs runtime `libpq5` and `curl`, creates non-root user `appuser` (UID 10001).
- **Security**: Runs unprivileged (`USER appuser`).
- **Entrypoint**: `docker/entrypoint.sh` performs automated PostgreSQL connectivity verification and runs `alembic -c backend/alembic.ini upgrade head` before starting the application.

### 1.2 Frontend Container (`Dockerfile.frontend`)
- **Base**: `node:20-alpine` (builder) $\to$ `nginx:1.27-alpine` (runner)
- **Multi-Stage Architecture**:
  - `builder`: Compiles TypeScript with `tsc -b` and builds optimized static assets with Vite.
  - `runner`: Serves compiled assets via Nginx with custom reverse proxy and caching rules.

---

## 2. Docker Compose Orchestration

### 2.1 Services
| Service | Image / Build | Port | Role |
| :--- | :--- | :--- | :--- |
| **`frontend`** | `Dockerfile.frontend` | `80:80` | Web server, static SPA fallback, and API reverse proxy |
| **`backend`** | `Dockerfile.backend` | `8000:8000` | FastAPI REST API and ML classification engine |
| **`celery_worker`** | `Dockerfile.backend` | Internal | Celery worker executing background repository scans |
| **`db`** | `postgres:16-alpine` | `5432` | Relational database with persistent volume |
| **`redis`** | `redis:7-alpine` | `6379` | In-memory message broker and Celery result backend |

### 2.2 Quickstart Commands

```bash
# Build and start all services
docker compose up --build -d

# Check service status and healthchecks
docker compose ps

# View backend logs
docker compose logs -f backend

# View Celery worker task processing
docker compose logs -f celery_worker

# Stop all services and maintain volume data
docker compose down
```

### 2.3 Compose Environments
- **`docker-compose.yml`**: Base definition with network, dependencies, and health probes.
- **`docker-compose.dev.yml`**: Mounts local directories (`./backend`, `./frontend/src`) for hot reloading and exposes DB ports.
- **`docker-compose.prod.yml`**: Hardens resource limits (`cpus`, `memory`), disables host DB exposure, and sets production JSON logging with rotation.
