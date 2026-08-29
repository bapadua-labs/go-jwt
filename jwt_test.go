// Testes de caixa-preta do pacote jwt.
package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

const testSecret = "sua-chave-secreta-com-pelo-menos-32-bytes"

// signedTokenWithHeader monta um JWT com header customizado e assinatura HMAC válida.
func signedTokenWithHeader(t *testing.T, header map[string]string, claims jwt.Claims, secret string) string {
	t.Helper()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerBase64 + "." + payloadBase64

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + signature
}

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

// TestSignHS256_WeakSecret verifica rejeição de assinatura com secret muito curto.
func TestSignHS256_WeakSecret(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	_, err := jwt.SignHS256(claims, "short")
	if !errors.Is(err, jwt.ErrWeakSecret) {
		t.Fatalf("esperava ErrWeakSecret, obteve: %v", err)
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

	_, err = jwt.VerifyHS256(token, "outro-secret-com-pelo-menos-32-bytes!!")
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

// TestVerifyHS256_InvalidHeader verifica rejeição de alg/typ inválidos no header.
func TestVerifyHS256_InvalidHeader(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tests := []struct {
		name   string
		header map[string]string
	}{
		{name: "alg none", header: map[string]string{"alg": "none", "typ": "JWT"}},
		{name: "alg RS256", header: map[string]string{"alg": "RS256", "typ": "JWT"}},
		{name: "alg ausente", header: map[string]string{"typ": "JWT"}},
		{name: "typ JWE", header: map[string]string{"alg": "HS256", "typ": "JWE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signedTokenWithHeader(t, tt.header, claims, testSecret)
			_, err := jwt.VerifyHS256(token, testSecret)
			if !errors.Is(err, jwt.ErrInvalidTokenType) {
				t.Fatalf("esperava ErrInvalidTokenType, obteve: %v", err)
			}
		})
	}
}

// TestVerifyHS256_EmptyTypAccepted verifica que typ omitido ainda é aceito com alg HS256.
func TestVerifyHS256_EmptyTypAccepted(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token := signedTokenWithHeader(t, map[string]string{"alg": "HS256"}, claims, testSecret)
	parsed, err := jwt.VerifyHS256(token, testSecret)
	if err != nil {
		t.Fatalf("esperava sucesso com typ vazio, obteve: %v", err)
	}
	if parsed["sub"] != claims["sub"] {
		t.Fatalf("sub diferente: %v != %v", parsed["sub"], claims["sub"])
	}
}

// TestVerifyHS256_WeakSecret verifica rejeição de verificação com secret muito curto.
func TestVerifyHS256_WeakSecret(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, "segredinho")
	if !errors.Is(err, jwt.ErrWeakSecret) {
		t.Fatalf("esperava ErrWeakSecret, obteve: %v", err)
	}
}
