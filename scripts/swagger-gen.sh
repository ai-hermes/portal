#!/usr/bin/env bash
set -euo pipefail

CGO_ENABLED=0 go run github.com/swaggo/swag/cmd/swag@v1.16.6 init \
  -g main.go \
  -d cmd/server,internal/api,internal/authn,internal/identity,internal/litellm,internal/litellmcredit,internal/models \
  -o docs \
  --parseInternal
