# Repository Guidelines

## Project Structure & Module Organization
- `cmd/server/`: backend entrypoint and runtime wiring (`main.go`), plus startup tests.
- `internal/`: core backend modules (`authn`, `authz`, `audit`, `litellm`, `api`, provider adapters under `internal/providers/*`).
- `frontend/`: Vite + React + TypeScript app (`src/pages`, `src/components`, `src/lib`).
- `docs/`: generated Swagger artifacts (`swagger.json`, `swagger.yaml`, `docs.go`).
- `scripts/`: utility scripts, including Swagger generation and OpenFGA initialization.
- `deploy/ecs/`: production compose/env templates for ECS-style deployments.

## Build, Test, and Development Commands
- Backend test: `go test ./...`  
  Runs all Go unit/integration tests (also required by CI).
- Backend run: `go run ./cmd/server`  
  Starts API server on `:8080` (requires Postgres + `JWT_SIGNING_KEY`).
- Swagger generation: `./scripts/swagger-gen.sh` or `go generate ./cmd/server`  
  Regenerates API docs in `docs/`.
- Frontend dev:
  `cd frontend && pnpm install && pnpm run dev`
- Frontend build:
  `cd frontend && pnpm run build`
- Local dependencies via Docker:
  `docker compose -f docker-compose.local.yml up`

## Coding Style & Naming Conventions
- Go: keep code `gofmt`-clean; package names lowercase; exported symbols use `CamelCase`; tests in `*_test.go`.
- TypeScript/React: 2-space indentation, `PascalCase` for page/component files (for example `LoginPage.tsx`), `camelCase` for variables/functions.
- Keep modules focused and colocate logic with its domain (`internal/<domain>` or `frontend/src/<feature>`).

## Testing Guidelines
- Primary framework is Go’s built-in `testing` package.
- Add/extend tests next to changed code (for example `internal/litellm/client_models_test.go`).
- Prefer table-driven tests for parsing/edge-case logic.
- Before opening a PR, run:
  - `go test ./...`
  - `cd frontend && pnpm run build` (CI validates buildability even though frontend test scripts are not defined yet).

## Commit & Pull Request Guidelines
- Follow Conventional Commit style seen in history: `feat(...)`, `fix(...)`, `chore(...)` (example: `feat(litellm): add model listing support and tests`).
- Keep commits scoped to one concern and include matching tests/docs updates.
- PRs should include:
  - concise problem/solution summary,
  - linked issue (if applicable),
  - verification steps/outputs,
  - notes for config/env changes (update `.env.example` or `deploy/ecs/.env.example` when needed).
- Ensure CI jobs pass: Go tests, frontend build, and Docker image builds.
