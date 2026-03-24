#!/bin/sh
set -eu

API_URL="${OPENFGA_API_URL:-http://openfga:8080}"
MODEL_VERSION="1.1"

echo "Waiting for OpenFGA at ${API_URL} ..."
until curl -fsS "${API_URL}/healthz" >/dev/null; do
  sleep 2
done

echo "Creating OpenFGA store..."
STORE_RES=$(curl -fsS -X POST "${API_URL}/stores" \
  -H 'content-type: application/json' \
  -d '{"name":"ai-hermas-local"}')

STORE_ID=$(echo "$STORE_RES" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
if [ -z "$STORE_ID" ]; then
  echo "failed to parse store id from: $STORE_RES"
  exit 1
fi

echo "Writing authorization model for store ${STORE_ID}..."
curl -fsS -X POST "${API_URL}/stores/${STORE_ID}/authorization-models" \
  -H 'content-type: application/json' \
  -d @- <<JSON
{
  "schema_version": "${MODEL_VERSION}",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "project",
      "relations": {
        "viewer": {
          "this": {}
        },
        "owner": {
          "this": {}
        }
      },
      "metadata": {
        "relations": {
          "viewer": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          },
          "owner": {
            "directly_related_user_types": [
              {
                "type": "user"
              }
            ]
          }
        }
      }
    }
  ]
}
JSON

echo "OpenFGA initialization complete."
echo "Set OPENFGA_STORE_ID=${STORE_ID} before starting backend with AUTHZ_PROVIDER=openfga"
