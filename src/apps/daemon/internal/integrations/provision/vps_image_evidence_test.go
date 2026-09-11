package provision

import (
	"strings"
	"testing"
)

func TestValidateRuntimeImageEvidenceAcceptsCompleteImmutableSet(t *testing.T) {
	evidence := strings.Join([]string{
		"/3xui_app sha256:" + strings.Repeat("a", 64),
		"/3xui_tor sha256:" + strings.Repeat("b", 64),
		"/3xui_postgres sha256:" + strings.Repeat("c", 64),
	}, "\n")
	if err := validateRuntimeImageEvidence(evidence); err != nil {
		t.Fatalf("validateRuntimeImageEvidence() error = %v", err)
	}
}

func TestValidateRuntimeImageEvidenceRejectsMissingContainer(t *testing.T) {
	evidence := strings.Join([]string{
		"/3xui_app sha256:" + strings.Repeat("a", 64),
		"/3xui_postgres sha256:" + strings.Repeat("c", 64),
	}, "\n")
	if err := validateRuntimeImageEvidence(evidence); err == nil || !strings.Contains(err.Error(), "missing deployed image ID") {
		t.Fatalf("validateRuntimeImageEvidence() error = %v, want missing-container failure", err)
	}
}

func TestValidateRuntimeImageEvidenceRejectsMutableOrMalformedIdentity(t *testing.T) {
	evidence := strings.Join([]string{
		"/3xui_app sha256:" + strings.Repeat("a", 64),
		"/3xui_tor sha256:" + strings.Repeat("b", 64),
		"/3xui_postgres postgres:16-alpine",
	}, "\n")
	if err := validateRuntimeImageEvidence(evidence); err == nil || !strings.Contains(err.Error(), "non-immutable image ID") {
		t.Fatalf("validateRuntimeImageEvidence() error = %v, want immutable-ID failure", err)
	}
}

func TestValidateRuntimeImageEvidenceRejectsUnexpectedContainer(t *testing.T) {
	evidence := strings.Join([]string{
		"/3xui_app sha256:" + strings.Repeat("a", 64),
		"/3xui_tor sha256:" + strings.Repeat("b", 64),
		"/3xui_postgres sha256:" + strings.Repeat("c", 64),
		"/unexpected sha256:" + strings.Repeat("d", 64),
	}, "\n")
	if err := validateRuntimeImageEvidence(evidence); err == nil || !strings.Contains(err.Error(), "unexpected deployed container") {
		t.Fatalf("validateRuntimeImageEvidence() error = %v, want unexpected-container failure", err)
	}
}
