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

## Frontend quick start

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `:5173` and proxies `/api` to `:8080`.

To build production static assets for Go server hosting:

```bash
cd frontend
npm run build
```

## Docker quick start

### Build images

```bash
docker build -f Dockerfile.backend -t ai-hermes-portal-backend:local .
```

The backend image now includes built frontend assets and serves both UI and API.

### Run local stack (backend + OpenFGA + Postgres)

```bash
docker compose up --build
```

Portal UI and backend API are both available at `http://localhost:8080`, and OpenFGA is at `http://localhost:8081`.

### Initialize OpenFGA model/store (optional profile)

```bash
docker compose --profile init up openfga-init
```

This prints a `OPENFGA_STORE_ID=<value>`; export it and start backend with `AUTHZ_PROVIDER=openfga`.

## v1 APIs

- `POST /api/v1/auth/register`
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

## Production integration path

- Replace `internal/providers/identitymem` with a ZITADEL adapter (OIDC/JWKS/user lookup)
- OpenFGA adapter is available under `internal/providers/authzopenfga`, enabled by `AUTHZ_PROVIDER=openfga`
- Replace `internal/providers/auditmem` with immutable storage (DB + object storage export)

## Runtime environment variables

- `PORT` default `:8080`
- `DATABASE_URL` Postgres DSN for account data
- `JWT_SIGNING_KEY` HMAC signing key for access token
- `ACCESS_TOKEN_TTL` default `15m`
- `REFRESH_TOKEN_TTL` default `720h`
- `EMAIL_CODE_TTL` default `10m`
- `PASSWORD_RESET_TTL` default `15m`
- `AUTHZ_PROVIDER` default `memory` (`openfga` to enable OpenFGA provider)
- `OPENFGA_API_URL` default `http://localhost:8081` for non-compose local runs
- `OPENFGA_STORE_ID` required when `AUTHZ_PROVIDER=openfga`
- `VITE_API_BASE_URL` optional frontend API prefix, default empty (same-origin)
- `WEB_DIST_DIR` frontend static directory for Go server hosting (default `frontend/dist`; container uses `/app/web`)
