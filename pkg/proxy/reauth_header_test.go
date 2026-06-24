package proxy

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestParseAuthCredentialIdentityDecodesBase64URLHeaderValues(t *testing.T) {
	headers := http.Header{}
	headers.Set(reauthCredentialIDHeader, "b64:"+base64.RawURLEncoding.EncodeToString([]byte("totp-alpha")))
	headers.Set(reauthCredentialNameHeader, "b64:"+base64.RawURLEncoding.EncodeToString([]byte("中文凭证")))
	headers.Set(reauthCredentialMethodHeader, "b64:"+base64.RawURLEncoding.EncodeToString([]byte("TOTP")))
	headers.Set(reauthLinkedTOTPIDHeader, "b64:"+base64.RawURLEncoding.EncodeToString([]byte("totp-alpha")))
	headers.Set(reauthLinkedTOTPNameHeader, "b64:"+base64.RawURLEncoding.EncodeToString([]byte("绑定中文")))

	identity := parseAuthCredentialIdentity(headers)
	if identity.credentialID != "totp-alpha" {
		t.Fatalf("credentialID = %q, want totp-alpha", identity.credentialID)
	}
	if identity.credentialName != "中文凭证" {
		t.Fatalf("credentialName = %q, want 中文凭证", identity.credentialName)
	}
	if identity.credentialMethod != "TOTP" {
		t.Fatalf("credentialMethod = %q, want TOTP", identity.credentialMethod)
	}
	if identity.linkedTOTPID != "totp-alpha" {
		t.Fatalf("linkedTOTPID = %q, want totp-alpha", identity.linkedTOTPID)
	}
	if identity.linkedTOTPName != "绑定中文" {
		t.Fatalf("linkedTOTPName = %q, want 绑定中文", identity.linkedTOTPName)
	}
}
