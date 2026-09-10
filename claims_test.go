// Testes unitários dos métodos de Claims.
package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

// TestClaims_HasValidExp valida os cenários de expiração da claim "exp".
func TestClaims_HasValidExp(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.Claims
		want   bool
	}{
		{
			name:   "exp no futuro",
			claims: jwt.Claims{"exp": time.Now().Add(time.Hour).Unix()},
			want:   true,
		},
		{
			name:   "exp no passado",
			claims: jwt.Claims{"exp": time.Now().Add(-time.Hour).Unix()},
			want:   false,
		},
		{
			name:   "exp na borda (now == exp)",
			claims: jwt.Claims{"exp": time.Now().Unix()},
			want:   false,
		},
		{
			name:   "sem exp",
			claims: jwt.Claims{"sub": "123"},
			want:   false,
		},
		{
			name:   "exp como float64",
			claims: jwt.Claims{"exp": float64(time.Now().Add(time.Hour).Unix())},
			want:   true,
		},
		{
			name:   "exp com tipo invalido",
			claims: jwt.Claims{"exp": "invalido"},
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

// TestClaims_ID valida o comportamento da claim "jti" (JWT ID).
func TestClaims_ID(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.Claims
		want   string
		wantOk bool
	}{

		{name: "jti string valida", claims: jwt.Claims{"jti": "abc-123"}, want: "abc-123", wantOk: true},
		{name: "sem jti", claims: jwt.Claims{"sub": "123"}, want: "", wantOk: false},
		{name: "claims vazias", claims: jwt.Claims{}, want: "", wantOk: false},
		{name: "jti string vazia", claims: jwt.Claims{"jti": ""}, want: "", wantOk: true},
		{name: "jti como float64", claims: jwt.Claims{"jti": float64(42)}, want: "", wantOk: false},
		{name: "jti como int", claims: jwt.Claims{"jti": 1}, want: "", wantOk: false},
		{name: "jti como bool", claims: jwt.Claims{"jti": true}, want: "", wantOk: false},
		{name: "jti com outras claims", claims: jwt.Claims{"jti": "uuid-1", "sub": "u1"}, want: "uuid-1", wantOk: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := tt.claims.ID()
			if gotID != tt.want {
				t.Fatalf("ID() = (%q, %v), want (%q, %v)", gotID, gotOK, tt.want, tt.wantOk)
			}
			if gotOK != tt.wantOk {
				t.Fatalf("ID() = (%q, %v), want (%q, %v)", gotID, gotOK, tt.want, tt.wantOk)
			}
		})
	}
}

// TestClaims_HasIssuer valida a claim "iss".
func TestClaims_HasIssuer(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.Claims
		expected string
		want     bool
	}{
		{name: "iss correto", claims: jwt.Claims{"iss": "go-jwt"}, expected: "go-jwt", want: true},
		{name: "iss incorreto", claims: jwt.Claims{"iss": "outro"}, expected: "go-jwt", want: false},
		{name: "sem iss", claims: jwt.Claims{"sub": "u1"}, expected: "go-jwt", want: false},
		{name: "iss tipo invalido", claims: jwt.Claims{"iss": 42}, expected: "go-jwt", want: false},
		{name: "iss string vazia esperada e presente", claims: jwt.Claims{"iss": ""}, expected: "", want: true},
		{name: "iss string vazia ausente", claims: jwt.Claims{}, expected: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.HasIssuer(tt.expected); got != tt.want {
				t.Fatalf("HasIssuer(%q) = %v, want %v", tt.expected, got, tt.want)
			}
		})
	}
}

// TestClaims_HasAudience valida a claim "aud" (string ou array).
func TestClaims_HasAudience(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.Claims
		expected string
		want     bool
	}{
		{name: "aud string correta", claims: jwt.Claims{"aud": "api"}, expected: "api", want: true},
		{name: "aud string incorreta", claims: jwt.Claims{"aud": "web"}, expected: "api", want: false},
		{name: "sem aud", claims: jwt.Claims{"sub": "u1"}, expected: "api", want: false},
		{name: "aud array contem esperado", claims: jwt.Claims{"aud": []interface{}{"web", "api"}}, expected: "api", want: true},
		{name: "aud array nao contem esperado", claims: jwt.Claims{"aud": []interface{}{"web", "mobile"}}, expected: "api", want: false},
		{name: "aud array vazio", claims: jwt.Claims{"aud": []interface{}{}}, expected: "api", want: false},
		{name: "aud tipo invalido", claims: jwt.Claims{"aud": true}, expected: "api", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.HasAudience(tt.expected); got != tt.want {
				t.Fatalf("HasAudience(%q) = %v, want %v", tt.expected, got, tt.want)
			}
		})
	}
}

// TestClaims_IssuedAt valida a extração da claim "iat".
func TestClaims_IssuedAt(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name   string
		claims jwt.Claims
		want   int64
		wantOk bool
	}{
		{name: "iat int64", claims: jwt.Claims{"iat": now}, want: now, wantOk: true},
		{name: "iat float64", claims: jwt.Claims{"iat": float64(now)}, want: now, wantOk: true},
		{name: "sem iat", claims: jwt.Claims{"sub": "u1"}, want: 0, wantOk: false},
		{name: "iat tipo invalido", claims: jwt.Claims{"iat": "agora"}, want: 0, wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.claims.IssuedAt()
			if got != tt.want || ok != tt.wantOk {
				t.Fatalf("IssuedAt() = (%d, %v), want (%d, %v)", got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

// TestClaims_IsValidNbf valida a claim "nbf".
func TestClaims_IsValidNbf(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.Claims
		want   bool
	}{
		{name: "sem nbf", claims: jwt.Claims{"sub": "u1"}, want: true},
		{name: "nbf no passado", claims: jwt.Claims{"nbf": time.Now().Add(-time.Hour).Unix()}, want: true},
		{name: "nbf na borda (now == nbf)", claims: jwt.Claims{"nbf": time.Now().Unix()}, want: true},
		{name: "nbf no futuro", claims: jwt.Claims{"nbf": time.Now().Add(time.Hour).Unix()}, want: false},
		{name: "nbf float64 futuro", claims: jwt.Claims{"nbf": float64(time.Now().Add(time.Hour).Unix())}, want: false},
		{name: "nbf tipo invalido (ignorado)", claims: jwt.Claims{"nbf": "depois"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.IsValidNbf(); got != tt.want {
				t.Fatalf("IsValidNbf() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestClaims_Validate valida o fluxo completo de iss/aud/tempo.
func TestClaims_Validate(t *testing.T) {
	validClaims := jwt.Claims{
		"iss": "go-jwt",
		"aud": "api",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
	}

	tests := []struct {
		name    string
		claims  jwt.Claims
		opts    jwt.VerifyOptions
		wantErr error
	}{
		{
			name:    "valido com iss e aud",
			claims:  validClaims,
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "api"},
			wantErr: nil,
		},
		{
			name:    "opts vazios nao exige iss/aud",
			claims:  jwt.Claims{"exp": time.Now().Add(time.Hour).Unix()},
			opts:    jwt.VerifyOptions{},
			wantErr: nil,
		},
		{
			name:    "so issuer preenchido",
			claims:  jwt.Claims{"iss": "go-jwt", "exp": time.Now().Add(time.Hour).Unix()},
			opts:    jwt.VerifyOptions{Issuer: "go-jwt"},
			wantErr: nil,
		},
		{
			name:    "expirado",
			claims:  jwt.Claims{"iss": "go-jwt", "aud": "api", "exp": time.Now().Add(-time.Hour).Unix()},
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "api"},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name:    "sem exp",
			claims:  jwt.Claims{"iss": "go-jwt", "aud": "api"},
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "api"},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name: "nbf no futuro",
			claims: jwt.Claims{
				"iss": "go-jwt",
				"aud": "api",
				"exp": time.Now().Add(time.Hour).Unix(),
				"nbf": time.Now().Add(time.Hour).Unix(),
			},
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "api"},
			wantErr: jwt.ErrInvalidNotBefore,
		},
		{
			name:    "issuer invalido",
			claims:  validClaims,
			opts:    jwt.VerifyOptions{Issuer: "outro", Audience: "api"},
			wantErr: jwt.ErrInvalidIssuer,
		},
		{
			name:    "audience invalida",
			claims:  validClaims,
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "web"},
			wantErr: jwt.ErrInvalidAudience,
		},
		{
			name: "audience em array",
			claims: jwt.Claims{
				"iss": "go-jwt",
				"aud": []interface{}{"web", "api"},
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			opts:    jwt.VerifyOptions{Issuer: "go-jwt", Audience: "api"},
			wantErr: nil,
		},
		{
			name: "maxAge valido",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-time.Minute).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour},
			wantErr: nil,
		},
		{
			name: "maxAge excedido",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-2 * time.Hour).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour},
			wantErr: jwt.ErrInvalidMaxAge,
		},
		{
			name:    "maxAge sem iat",
			claims:  jwt.Claims{"exp": time.Now().Add(time.Hour).Unix()},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour},
			wantErr: jwt.ErrInvalidIssuedAt,
		},
		{
			name: "maxAge com iat tipo invalido",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": "ontem",
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour},
			wantErr: jwt.ErrInvalidIssuedAt,
		},
		{
			name: "iat no futuro",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(time.Hour).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour},
			wantErr: jwt.ErrInvalidIssuedAt,
		},
		{
			name: "maxAge zero nao exige iat",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: 0},
			wantErr: nil,
		},
		{
			name: "exp expirado dentro do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(-30 * time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: nil,
		},
		{
			name: "exp expirado fora do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(-2 * time.Minute).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name: "nbf futuro dentro do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"nbf": time.Now().Add(30 * time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: nil,
		},
		{
			name: "nbf futuro fora do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"nbf": time.Now().Add(2 * time.Minute).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: jwt.ErrInvalidNotBefore,
		},
		{
			name: "iat futuro dentro do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(30 * time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour, EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: nil,
		},
		{
			name: "iat futuro fora do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(2 * time.Minute).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Hour, EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: jwt.ErrInvalidIssuedAt,
		},
		{
			name: "maxAge excedido dentro do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-90 * time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Minute, EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: nil,
		},
		{
			name: "maxAge excedido fora do skew",
			claims: jwt.Claims{
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Add(-3 * time.Minute).Unix(),
			},
			opts:    jwt.VerifyOptions{MaxAge: time.Minute, EnableClockSkew: true, ClockSkew: time.Minute},
			wantErr: jwt.ErrInvalidMaxAge,
		},
		{
			name: "toggle desligado ignora ClockSkew",
			claims: jwt.Claims{
				"exp": time.Now().Add(-30 * time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: false, ClockSkew: time.Minute},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name: "toggle ligado com skew zero: exp recente rejeitado",
			claims: jwt.Claims{
				"exp": time.Now().Add(-time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: 0},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name: "skew negativo tratado como zero",
			claims: jwt.Claims{
				"exp": time.Now().Add(-time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: -time.Minute},
			wantErr: jwt.ErrExpiredToken,
		},
		{
			name: "subsegundo de skew truncado para zero",
			claims: jwt.Claims{
				"exp": time.Now().Add(-time.Second).Unix(),
			},
			opts:    jwt.VerifyOptions{EnableClockSkew: true, ClockSkew: 500 * time.Millisecond},
			wantErr: jwt.ErrExpiredToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate(tt.opts)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() erro inesperado: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestClaims_Validate_Revocation valida checagem opcional via RevocationStore.
func TestClaims_Validate_Revocation(t *testing.T) {
	validExp := time.Now().Add(time.Hour).Unix()
	revoked := map[string]bool{"revoked-id": true}

	store := jwt.RevocationFunc(func(jti string) bool {
		return revoked[jti]
	})

	tests := []struct {
		name    string
		claims  jwt.Claims
		opts    jwt.VerifyOptions
		wantErr error
	}{
		{
			name:    "store nil nao checa",
			claims:  jwt.Claims{"exp": validExp, "jti": "revoked-id"},
			opts:    jwt.VerifyOptions{},
			wantErr: nil,
		},
		{
			name:    "jti ausente com store ignora checagem",
			claims:  jwt.Claims{"exp": validExp},
			opts:    jwt.VerifyOptions{RevocationStore: store},
			wantErr: nil,
		},
		{
			name:    "jti tipo invalido com store ignora checagem",
			claims:  jwt.Claims{"exp": validExp, "jti": float64(1)},
			opts:    jwt.VerifyOptions{RevocationStore: store},
			wantErr: nil,
		},
		{
			name:    "jti nao revogado",
			claims:  jwt.Claims{"exp": validExp, "jti": "active-id"},
			opts:    jwt.VerifyOptions{RevocationStore: store},
			wantErr: nil,
		},
		{
			name:    "jti revogado",
			claims:  jwt.Claims{"exp": validExp, "jti": "revoked-id"},
			opts:    jwt.VerifyOptions{RevocationStore: store},
			wantErr: jwt.ErrTokenRevoked,
		},
		{
			name:    "jti vazio consulta o store",
			claims:  jwt.Claims{"exp": validExp, "jti": ""},
			opts:    jwt.VerifyOptions{RevocationStore: jwt.RevocationFunc(func(jti string) bool { return jti == "" })},
			wantErr: jwt.ErrTokenRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate(tt.opts)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() erro inesperado: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
