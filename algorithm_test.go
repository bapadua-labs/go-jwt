package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

// TestAlgorithm_Valid verifica se o algoritmo é válido.
func TestAlgorithm_Valid(t *testing.T) {
	tests := []struct {
		name string
		alg  jwt.Algorithm
		want bool
	}{
		{name: "HS256", alg: jwt.AlgorithmHS256, want: true},
		{name: "none", alg: jwt.Algorithm("none"), want: false},
		{name: "vazio", alg: jwt.Algorithm(""), want: false},
		{name: "RS256 - const", alg: jwt.AlgorithmRS256, want: true},
		{name: "RS256 - string", alg: jwt.Algorithm("RS256"), want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.alg.Valid()
			if got != test.want {
				t.Errorf("Valid() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestAlgorithm_String verifica se a string do algoritmo é correta.
func TestAlgorithm_String(t *testing.T) {
	if got := jwt.AlgorithmHS256.String(); got != "HS256" {
		t.Errorf("String() = %v, want %v", got, "HS256")
	}
	if got := jwt.AlgorithmRS256.String(); got != "RS256" {
		t.Errorf("String() = %v, want %v", got, "RS256")
	}
}

func TestAlgoritmConfusion(t *testing.T) {
	testSecret := "my-secret-32-bytes-length-test-secret"
	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Erro ao gerar chave privada: %v", err)
	}

	t.Run("RS256 nao verifica corretamente tokens HS256", func(t *testing.T) {
		token, err := jwt.SignRS256(claims, privateKey)
		if err != nil {
			t.Fatalf("Erro ao assinar token: %v", err)
		}

		_, err = jwt.VerifyHS256(token, testSecret)
		if !errors.Is(err, jwt.ErrInvalidSignature) {
			t.Fatalf("esperava ErrInvalidSignature, obteve: %v", err)
		}
	})

	t.Run("HS256 nao verifica corretamente tokens RS256", func(t *testing.T) {
		token, err := jwt.SignHS256(claims, testSecret)
		if err != nil {
			t.Fatalf("Erro ao assinar token: %v", err)
		}

		_, err = jwt.VerifyRS256(token, &privateKey.PublicKey)
		if !errors.Is(err, jwt.ErrInvalidTokenType) {
			t.Fatalf("esperava ErrInvalidTokenType, obteve: %v", err)
		}
	})

	// Ataque clássico: forja HS256 usando a chave pública RSA como secret HMAC.
	// VerifyRS256 deve rejeitar pelo alg do header (não tratar como RS256).
	t.Run("RS256 rejeita token HS256 forjado com chave publica", func(t *testing.T) {
		pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Erro ao serializar chave pública: %v", err)
		}
		hmacSecret := string(pubDER)

		token := signedTokenWithHeader(t, map[string]string{
			"alg": "HS256",
			"typ": "JWT",
		}, claims, hmacSecret)

		_, err = jwt.VerifyRS256(token, &privateKey.PublicKey)
		if !errors.Is(err, jwt.ErrInvalidTokenType) {
			t.Fatalf("esperava ErrInvalidTokenType, obteve: %v", err)
		}
	})
}
