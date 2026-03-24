package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/warjiang/portal/internal/api"
	"github.com/warjiang/portal/internal/audit"
	"github.com/warjiang/portal/internal/auth"
	"github.com/warjiang/portal/internal/authz"
	"github.com/warjiang/portal/internal/identity"
	"github.com/warjiang/portal/internal/providers/auditmem"
	"github.com/warjiang/portal/internal/providers/authzmem"
	"github.com/warjiang/portal/internal/providers/authzopenfga"
	"github.com/warjiang/portal/internal/providers/identitymem"
)

func main() {
	identityProvider := identitymem.NewProvider()
	auditStore := auditmem.NewStore()
	auditSvc := audit.NewService(auditStore)
	authzProvider := selectAuthzProvider()

	authSvc := auth.NewService(identityProvider)
	identitySvc := identity.NewService(identityProvider)
	authzSvc := authz.NewService(authzProvider)

	router := api.NewRouter(api.Dependencies{
		Auth:     authSvc,
		Identity: identitySvc,
		Authz:    authzSvc,
		Audit:    auditSvc,
	})
	webDir := envOr("WEB_DIST_DIR", "frontend/dist")
	handler := api.NewAppHandler(router, webDir)
	if handler == router {
		log.Printf("frontend assets unavailable at %s, serving API only", webDir)
	} else {
		if abs, err := filepath.Abs(webDir); err == nil {
			webDir = abs
		}
		log.Printf("serving frontend assets from %s", webDir)
	}

	srv := &http.Server{
		Addr:              envOr("PORT", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("portal backend listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func selectAuthzProvider() authz.Provider {
	switch envOr("AUTHZ_PROVIDER", "memory") {
	case "openfga":
		apiURL := envOr("OPENFGA_API_URL", "http://localhost:8081")
		storeID := os.Getenv("OPENFGA_STORE_ID")
		if storeID == "" {
			log.Printf("AUTHZ_PROVIDER=openfga but OPENFGA_STORE_ID is empty, fallback to memory")
			return authzmem.NewProvider()
		}
		log.Printf("using OpenFGA authz provider: api_url=%s store_id=%s", apiURL, storeID)
		return authzopenfga.NewProvider(apiURL, storeID)
	default:
		log.Printf("using in-memory authz provider")
		return authzmem.NewProvider()
	}
}
