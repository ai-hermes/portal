package authn

import (
	"testing"
	"time"
)

func TestValidateCNPhone(t *testing.T) {
	if err := validateCNPhone("13812345678"); err != nil {
		t.Fatalf("expected valid phone, got %v", err)
	}
	if err := validateCNPhone("+8613812345678"); err == nil {
		t.Fatalf("expected invalid phone")
	}
	if err := validateCNPhone("123"); err == nil {
		t.Fatalf("expected invalid phone")
	}
}

func TestFormatPGInterval(t *testing.T) {
	if got := formatPGInterval(10 * time.Minute); got != "600 seconds" {
		t.Fatalf("expected 600 seconds, got %s", got)
	}
	if got := formatPGInterval(0); got != "1 seconds" {
		t.Fatalf("expected 1 seconds, got %s", got)
	}
}
