# AI-Hermes Portal (4A v1 Skeleton)

This repository implements a practical v1 skeleton of a 4A portal with:

- Backend: Go + Gin HTTP APIs (`/api/v1/*`) with Postgres-backed account authn and pluggable AuthZ/Audit
- Frontend: Vite + React + TailwindCSS + shadcn-style UI primitives
- Current providers: in-memory dev providers (replaceable with ZITADEL/OpenFGA adapters)

## Backend quick start

```bash
go test ./...
go run ./cmd/server
```

Server runs on `:8080` by default.

Backend requires Postgres and `JWT_SIGNING_KEY`; schema is auto-migrated on startup.

## Swagger docs

Generate Swagger artifacts:

```bash
./scripts/swagger-gen.sh
```

Or:

```bash
go generate ./cmd/server
```

After backend starts, Swagger UI is available at `http://localhost:8080/swagger/index.html`.

## Frontend quick start

```bash
cd frontend
pnpm install
pnpm run dev
```

Frontend runs on `:5173` and proxies `/api` to `:8080`.

To build production static assets for Go server hosting:

```bash
cd frontend
pnpm run build
```

## Docker quick start

### Build images

```bash
docker build -f Dockerfile.backend -t ai-hermes-portal-backend:local .
```

The backend image now includes built frontend assets and serves both UI and API.

For private registry mirror of base images (set `IMAGE_REGISTRY` without trailing `/`, for example `registry.example.com/dockerhub`):

```bash
docker build \
  --build-arg IMAGE_REGISTRY=registry.example.com/dockerhub \
  -f Dockerfile.backend \
  -t ai-hermes-portal-backend:local .
```

### Run local stack (backend + OpenFGA + Postgres)

```bash
docker compose up --build
```

Portal UI and backend API are both available at `http://localhost:8080`, and OpenFGA is at `http://localhost:8081`.

For non-build startup, point `BACKEND_IMAGE` to a prebuilt image and run without `--build`:

```bash
BACKEND_IMAGE=registry.example.com/dockerhub/ai-hermes-portal/backend:latest docker compose up
# or explicitly prevent build:
docker compose up --no-build
```

### Local development without building backend/frontend images

Use `docker-compose.local.yml` to start only dependencies (Postgres/OpenFGA), and run backend/frontend on host:

```bash
docker compose -f docker-compose.local.yml up
```

Then start apps on host:

```bash
go run ./cmd/server
cd frontend && pnpm install && pnpm run dev
```

Backend API runs at `http://localhost:8080`, frontend dev server at `http://localhost:5173`, OpenFGA at `http://localhost:8081`.

Compose uses `IMAGE_REGISTRY` to build/pull all base images (default `docker.io`).  
Set `IMAGE_REGISTRY` in `.env` (or export it in shell):

```bash
IMAGE_REGISTRY=registry.example.com/dockerhub
BACKEND_IMAGE=registry.example.com/dockerhub/ai-hermes-portal/backend:latest
```

### Initialize OpenFGA model/store (optional profile)

```bash
docker compose --profile init up openfga-init
```

This prints a `OPENFGA_STORE_ID=<value>`; export it and start backend with `AUTHZ_PROVIDER=openfga`.

## Aliyun ECS deployment

For ECS compose deployment with **external Postgres** and **OpenFGA in compose**, use:

```bash
cp deploy/ecs/.env.example deploy/ecs/.env
docker compose --env-file deploy/ecs/.env -f deploy/ecs/docker-compose.prod.yml up -d
```

Notes:
- `DATABASE_URL` and `OPENFGA_DATASTORE_URI` should both point to external PostgreSQL (for example, ApsaraDB RDS PostgreSQL).
- `OPENFGA_API_URL` defaults to `http://openfga:8080` (in-compose service discovery).
- `OPENFGA_STORE_ID` must be prepared in advance for backend `AUTHZ_PROVIDER=openfga`.

## v1 APIs

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/register/phone`
- `POST /api/v1/auth/sms/send-code`
- `POST /api/v1/auth/verify-email`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/password/change`
- `POST /api/v1/auth/password/forgot`
- `POST /api/v1/auth/password/reset`
- `GET /api/v1/me`
- `GET /api/v1/tenants/:id/members`
- `POST /api/v1/permissions/check`
- `POST /api/v1/policies/relationships`
- `GET /api/v1/audit/events`
- `GET /api/v1/config/litellm`
- `GET /api/v1/litellm/me/models`
- `GET /api/v1/admin/litellm/credits/:tenant_id/:user_id`
- `POST /api/v1/admin/litellm/credits/adjust`
- `GET /api/v1/admin/litellm/events`

## Production integration path

- Replace `internal/providers/identitymem` with a ZITADEL adapter (OIDC/JWKS/user lookup)
- OpenFGA adapter is available under `internal/providers/authzopenfga`, enabled by `AUTHZ_PROVIDER=openfga`
- Replace `internal/providers/auditmem` with immutable storage (DB + object storage export)

## Runtime environment variables

- `PORT` default `:8080`
- `DOTENV_FILES` dotenv files load order (comma-separated), default `.env.local,.env`
- `DATABASE_URL` Postgres DSN for account data
- `JWT_SIGNING_KEY` HMAC signing key for access token
- `ACCESS_TOKEN_TTL` default `15m`
- `REFRESH_TOKEN_TTL` default `720h`
- `EMAIL_CODE_TTL` default `10m`
- `SMS_CODE_TTL` default `10m`
- `SMS_RATE_WINDOW` default `10m`
- `SMS_RESEND_INTERVAL` default `60s`
- `SMS_MAX_PER_PHONE` default `5`
- `SMS_MAX_PER_IP` default `20`
- `PASSWORD_RESET_TTL` default `15m`
- `LITELLM_BASE_URL` LiteLLM service base URL, default `https://llmv2.spotty.com.cn/`
- `LITELLM_DEFAULT_MODEL` client-facing default LiteLLM model, default `gpt-4o-mini`
- `LITELLM_MASTER_KEY` LiteLLM master/admin key
- `LITELLM_HTTP_TIMEOUT` LiteLLM API timeout, default `5s`
- `LITELLM_DEFAULT_USER_QUOTA` auto-provision quota for new/first-login users, default `10`
- `PLATFORM_ADMIN_EMAILS` comma-separated emails allowed to manage LiteLLM credits
- `SMS_PROVIDER` default `log` (`aliyun` to enable Alibaba Cloud SMS provider)
- `ALIBABA_CLOUD_REGION_ID` default `cn-hangzhou`
- `ALIBABA_CLOUD_ACCESS_KEY_ID` required when `SMS_PROVIDER=aliyun`
- `ALIBABA_CLOUD_ACCESS_KEY_SECRET` required when `SMS_PROVIDER=aliyun`
- `ALIYUN_SMS_SIGN_NAME` required when `SMS_PROVIDER=aliyun`
- `ALIYUN_SMS_TEMPLATE_CODE_REGISTER` required when `SMS_PROVIDER=aliyun`
- `AUTHZ_PROVIDER` default `memory` (`openfga` to enable OpenFGA provider)
- `OPENFGA_API_URL` default `http://localhost:8081` for non-compose local runs
- `OPENFGA_STORE_ID` required when `AUTHZ_PROVIDER=openfga`
- `VITE_API_BASE_URL` optional frontend API prefix, default empty (same-origin)
- `WEB_DIST_DIR` frontend static directory for Go server hosting (default `frontend/dist`; container uses `/app/web`)

`POST /api/v1/auth/login` now accepts `account` (email or phone) + `password`. For compatibility it still accepts legacy `email` + `password`.
