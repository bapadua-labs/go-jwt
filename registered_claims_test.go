package jwt

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAudience_MarshalUnmarshal(t *testing.T) {
	t.Run("string única", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`"api"`), &a); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if len(a) != 1 || a[0] != "api" {
			t.Fatalf("Audience = %#v", a)
		}
		out, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(out) != `"api"` {
			t.Fatalf("Marshal = %s", out)
		}
	})

	t.Run("array", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`["a","b"]`), &a); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if len(a) != 2 || a[0] != "a" || a[1] != "b" {
			t.Fatalf("Audience = %#v", a)
		}
		out, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if string(out) != `["a","b"]` {
			t.Fatalf("Marshal = %s", out)
		}
	})

	t.Run("null e vazio", func(t *testing.T) {
		var a Audience
		if err := json.Unmarshal([]byte(`null`), &a); err != nil {
			t.Fatalf("Unmarshal null: %v", err)
		}
		if a != nil {
			t.Fatalf("esperava nil, obteve %#v", a)
		}
		out, err := json.Marshal(Audience{})
		if err != nil {
			t.Fatalf("Marshal vazio: %v", err)
		}
		if string(out) != `null` {
			t.Fatalf("Marshal vazio = %s", out)
		}
	})
}

func TestRegisteredClaims_Validate(t *testing.T) {
	now := time.Now().Unix()

	t.Run("exp válido", func(t *testing.T) {
		c := RegisteredClaims{ExpiresAt: now + 3600}
		if err := c.Validate(VerifyOptions{}); err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("exp ausente", func(t *testing.T) {
		c := RegisteredClaims{}
		if err := c.Validate(VerifyOptions{}); !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
		}
	})

	t.Run("iss e aud", func(t *testing.T) {
		c := RegisteredClaims{
			Issuer:    "issuer",
			Audience:  Audience{"api"},
			ExpiresAt: now + 3600,
		}
		if err := c.Validate(VerifyOptions{Issuer: "issuer", Audience: "api"}); err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if err := c.Validate(VerifyOptions{Audience: "other"}); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("esperava ErrInvalidAudience, obteve: %v", err)
		}
	})
}
