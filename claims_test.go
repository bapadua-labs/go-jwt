// Testes unitários dos métodos de Claims.
package jwt

import (
	"testing"
	"time"
)

// TestClaims_HasValidExp valida os cenários de expiração da claim "exp".
func TestClaims_HasValidExp(t *testing.T) {
	tests := []struct {
		name   string
		claims Claims
		want   bool
	}{
		{
			name:   "exp no futuro",
			claims: Claims{"exp": time.Now().Add(time.Hour).Unix()},
			want:   true,
		},
		{
			name:   "exp no passado",
			claims: Claims{"exp": time.Now().Add(-time.Hour).Unix()},
			want:   false,
		},
		{
			name:   "sem exp",
			claims: Claims{"sub": "123"},
			want:   false,
		},
		{
			name:   "exp como float64",
			claims: Claims{"exp": float64(time.Now().Add(time.Hour).Unix())},
			want:   true,
		},
		{
			name:   "exp com tipo invalido",
			claims: Claims{"exp": "invalido"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.HasValidExp(); got != tt.want {
				t.Fatalf("HasValidExp() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestClaims_IsExpired valida o comportamento inverso de HasValidExp.
func TestClaims_IsExpired(t *testing.T) {
	tests := []struct {
		name   string
		claims Claims
		want   bool
	}{
		{
			name:   "exp no futuro",
			claims: Claims{"exp": time.Now().Add(time.Hour).Unix()},
			want:   false,
		},
		{
			name:   "exp no passado",
			claims: Claims{"exp": time.Now().Add(-time.Hour).Unix()},
			want:   true,
		},
		{
			name:   "sem exp",
			claims: Claims{"sub": "123"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.IsExpired(); got != tt.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
