// Testes de caixa-preta do pacote jwt.
package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

const testSecret = "minha-chave-secreta"

// TestSignAndVerify valida o fluxo completo de assinatura e verificação com HS256.
func TestSignAndVerify(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	parsedClaims, err := jwt.VerifyHS256(token, testSecret)
	if err != nil {
		t.Fatalf("Erro ao verificar token: %v", err)
	}

	if parsedClaims["sub"] != claims["sub"] {
		t.Fatalf("Sub claim diferente: %v != %v", parsedClaims["sub"], claims["sub"])
	}

	expParsed := parsedClaims["exp"].(float64)
	expOriginal := float64(claims["exp"].(int64))

	if expParsed != expOriginal {
		t.Fatalf("Exp claim diferente: %v != %v", expParsed, expOriginal)
	}
}

// TestVerifyHS256_ExpiredToken verifica rejeição de token com exp no passado.
func TestVerifyHS256_ExpiredToken(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, testSecret)
	if !errors.Is(err, jwt.ErrExpiredToken) {
		t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
	}
}

// TestVerifyHS256_MissingExp verifica rejeição de token sem claim "exp".
func TestVerifyHS256_MissingExp(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, testSecret)
	if !errors.Is(err, jwt.ErrExpiredToken) {
		t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
	}
}

// TestVerifyHS256_InvalidExpType verifica rejeição quando "exp" tem tipo inválido.
func TestVerifyHS256_InvalidExpType(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": "amanha",
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, testSecret)
	if !errors.Is(err, jwt.ErrExpiredToken) {
		t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
	}
}

// TestVerifyHS256_InvalidSignature verifica rejeição de assinatura adulterada.
func TestVerifyHS256_InvalidSignature(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[2] = parts[2][:len(parts[2])-1] + "X"
	tamperedToken := strings.Join(parts, ".")

	_, err = jwt.VerifyHS256(tamperedToken, testSecret)
	if !errors.Is(err, jwt.ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature, obteve: %v", err)
	}
}

// TestVerifyHS256_WrongSecret verifica rejeição com secret incorreto.
func TestVerifyHS256_WrongSecret(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, "outro-secret")
	if !errors.Is(err, jwt.ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature, obteve: %v", err)
	}
}

// TestVerifyHS256_MalformedToken verifica rejeição de tokens malformados.
func TestVerifyHS256_MalformedToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "vazio", token: ""},
		{name: "uma parte", token: "somenteheader"},
		{name: "duas partes", token: "header.payload"},
		{name: "quatro partes", token: "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jwt.VerifyHS256(tt.token, testSecret)
			if !errors.Is(err, jwt.ErrInvalidToken) {
				t.Fatalf("esperava ErrInvalidToken, obteve: %v", err)
			}
		})
	}
}
