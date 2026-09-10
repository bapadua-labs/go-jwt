// Testes de caixa-preta do pacote jwt.
package jwt_test

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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

// generateRSAKey gera uma chave RSA 2048 bits para testes.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Erro ao gerar chave privada: %v", err)
	}
	return key
}

// signedRS256TokenWithHeader monta um JWT com header customizado e assinatura RSA válida.
func signedRS256TokenWithHeader(t *testing.T, header map[string]string, claims jwt.Claims, privateKey *rsa.PrivateKey) string {
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
	unsignedToken := headerBase64 + "." + payloadBase64

	hasher := sha256.New()
	hasher.Write([]byte(unsignedToken))
	hashed := hasher.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("assinar RS256: %v", err)
	}

	return unsignedToken + "." + base64.RawURLEncoding.EncodeToString(signatureBytes)
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

// TestSignHS256_InvalidPayload verifica ErrInvalidPayload quando claims não serializam.
func TestSignHS256_InvalidPayload(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"bad": make(chan int),
	}

	_, err := jwt.SignHS256(claims, testSecret)
	if !errors.Is(err, jwt.ErrInvalidPayload) {
		t.Fatalf("esperava ErrInvalidPayload, obteve: %v", err)
	}
}

// TestSignRS256_InvalidPayload verifica ErrInvalidPayload quando claims não serializam.
func TestSignRS256_InvalidPayload(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"bad": make(chan int),
	}

	_, err := jwt.SignRS256(claims, privateKey)
	if !errors.Is(err, jwt.ErrInvalidPayload) {
		t.Fatalf("esperava ErrInvalidPayload, obteve: %v", err)
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

func Test_RS256(t *testing.T) {
	privateKey := generateRSAKey(t)
	publicKey := &privateKey.PublicKey

	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	token, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	parsedClaims, err := jwt.VerifyRS256(token, publicKey)
	if err != nil {
		t.Fatalf("Erro ao verificar token: %v", err)
	}

	sub, _ := parsedClaims["sub"].(string)
	if sub != "admin" {
		t.Fatalf("sub diferente: %v != %v", sub, "admin")
	}
}

func Test_RS256_InvalidSignature(t *testing.T) {
	trueKey := generateRSAKey(t)
	hackerKey := generateRSAKey(t)

	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	hackerToken, err := jwt.SignRS256(claims, hackerKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyRS256(hackerToken, &trueKey.PublicKey)
	if !errors.Is(err, jwt.ErrInvalidSignature) {
		t.Fatalf("esperava ErrInvalidSignature, obteve: %v", err)
	}
}

// TestVerifyRS256_ExpiredToken verifica rejeição de token com exp no passado.
func TestVerifyRS256_ExpiredToken(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}

	token, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyRS256(token, &privateKey.PublicKey)
	if !errors.Is(err, jwt.ErrExpiredToken) {
		t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
	}
}

// TestVerifyRS256_MissingExp verifica rejeição de token sem claim "exp".
func TestVerifyRS256_MissingExp(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "admin",
	}

	token, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyRS256(token, &privateKey.PublicKey)
	if !errors.Is(err, jwt.ErrExpiredToken) {
		t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
	}
}

// TestVerifyRS256_MalformedToken verifica rejeição de tokens malformados.
func TestVerifyRS256_MalformedToken(t *testing.T) {
	privateKey := generateRSAKey(t)

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
			_, err := jwt.VerifyRS256(tt.token, &privateKey.PublicKey)
			if !errors.Is(err, jwt.ErrInvalidToken) {
				t.Fatalf("esperava ErrInvalidToken, obteve: %v", err)
			}
		})
	}
}

// TestVerifyRS256_InvalidTyp verifica rejeição quando typ é inválido.
func TestVerifyRS256_InvalidTyp(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}

	token := signedRS256TokenWithHeader(t, map[string]string{
		"alg": "RS256",
		"typ": "JWE",
	}, claims, privateKey)

	_, err := jwt.VerifyRS256(token, &privateKey.PublicKey)
	if !errors.Is(err, jwt.ErrInvalidTokenType) {
		t.Fatalf("esperava ErrInvalidTokenType, obteve: %v", err)
	}
}

// TestVerifyHS256_NbfFuture verifica rejeição automática de nbf no futuro.
func TestVerifyHS256_NbfFuture(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyHS256(token, testSecret)
	if !errors.Is(err, jwt.ErrInvalidNotBefore) {
		t.Fatalf("esperava ErrInvalidNotBefore, obteve: %v", err)
	}
}

// TestVerifyHS256WithOptions valida iss/aud na verificação HS256.
func TestVerifyHS256WithOptions(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"iss": "go-jwt",
		"aud": "api",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	t.Run("sucesso", func(t *testing.T) {
		parsed, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			Issuer:   "go-jwt",
			Audience: "api",
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if parsed["sub"] != claims["sub"] {
			t.Fatalf("sub diferente: %v", parsed["sub"])
		}
	})

	t.Run("opts vazios ignora iss/aud", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("issuer invalido", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			Issuer: "outro",
		})
		if !errors.Is(err, jwt.ErrInvalidIssuer) {
			t.Fatalf("esperava ErrInvalidIssuer, obteve: %v", err)
		}
	})

	t.Run("audience invalida", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			Audience: "web",
		})
		if !errors.Is(err, jwt.ErrInvalidAudience) {
			t.Fatalf("esperava ErrInvalidAudience, obteve: %v", err)
		}
	})
}

// TestVerifyHS256WithOptions_ClockSkew valida tolerância de relógio na verificação HS256.
func TestVerifyHS256WithOptions_ClockSkew(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(-30 * time.Second).Unix(),
	}

	token, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	t.Run("expirado dentro do skew", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			EnableClockSkew: true,
			ClockSkew:       time.Minute,
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("toggle desligado ignora ClockSkew", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			EnableClockSkew: false,
			ClockSkew:       time.Minute,
		})
		if !errors.Is(err, jwt.ErrExpiredToken) {
			t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
		}
	})

	t.Run("sem skew rejeita", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{})
		if !errors.Is(err, jwt.ErrExpiredToken) {
			t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
		}
	})
}

// TestVerifyRS256_NbfFuture verifica rejeição automática de nbf no futuro no RS256.
func TestVerifyRS256_NbfFuture(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "admin",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	_, err = jwt.VerifyRS256(token, &privateKey.PublicKey)
	if !errors.Is(err, jwt.ErrInvalidNotBefore) {
		t.Fatalf("esperava ErrInvalidNotBefore, obteve: %v", err)
	}
}

// TestVerifyRS256WithOptions valida iss/aud na verificação RS256.
func TestVerifyRS256WithOptions(t *testing.T) {
	privateKey := generateRSAKey(t)
	claims := jwt.Claims{
		"sub": "admin",
		"iss": "go-jwt",
		"aud": "api",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar token: %v", err)
	}

	t.Run("sucesso", func(t *testing.T) {
		parsed, err := jwt.VerifyRS256WithOptions(token, &privateKey.PublicKey, jwt.VerifyOptions{
			Issuer:   "go-jwt",
			Audience: "api",
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if parsed["sub"] != "admin" {
			t.Fatalf("sub diferente: %v", parsed["sub"])
		}
	})

	t.Run("issuer invalido", func(t *testing.T) {
		_, err := jwt.VerifyRS256WithOptions(token, &privateKey.PublicKey, jwt.VerifyOptions{
			Issuer: "outro",
		})
		if !errors.Is(err, jwt.ErrInvalidIssuer) {
			t.Fatalf("esperava ErrInvalidIssuer, obteve: %v", err)
		}
	})
}

// TestVerifyWithOptions_MaxTokenLen valida o limite de tamanho do token em HS256 e RS256.
func TestVerifyWithOptions_MaxTokenLen(t *testing.T) {
	claims := jwt.Claims{
		"sub": "1234567890",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	hsToken, err := jwt.SignHS256(claims, testSecret)
	if err != nil {
		t.Fatalf("Erro ao assinar HS256: %v", err)
	}

	privateKey := generateRSAKey(t)
	rsToken, err := jwt.SignRS256(claims, privateKey)
	if err != nil {
		t.Fatalf("Erro ao assinar RS256: %v", err)
	}

	t.Run("HS256 aceita len igual ao limite", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(hsToken, testSecret, jwt.VerifyOptions{
			MaxTokenLen: len(hsToken),
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("HS256 rejeita token maior que o limite", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(hsToken, testSecret, jwt.VerifyOptions{
			MaxTokenLen: len(hsToken) - 1,
		})
		if !errors.Is(err, jwt.ErrTokenTooLarge) {
			t.Fatalf("esperava ErrTokenTooLarge, obteve: %v", err)
		}
	})

	t.Run("HS256 MaxTokenLen zero nao limita", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions(hsToken, testSecret, jwt.VerifyOptions{
			MaxTokenLen: 0,
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("HS256 token vazio", func(t *testing.T) {
		_, err := jwt.VerifyHS256WithOptions("", testSecret, jwt.VerifyOptions{})
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("esperava ErrInvalidToken, obteve: %v", err)
		}
	})

	t.Run("RS256 aceita len igual ao limite", func(t *testing.T) {
		_, err := jwt.VerifyRS256WithOptions(rsToken, &privateKey.PublicKey, jwt.VerifyOptions{
			MaxTokenLen: len(rsToken),
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("RS256 rejeita token maior que o limite", func(t *testing.T) {
		_, err := jwt.VerifyRS256WithOptions(rsToken, &privateKey.PublicKey, jwt.VerifyOptions{
			MaxTokenLen: len(rsToken) - 1,
		})
		if !errors.Is(err, jwt.ErrTokenTooLarge) {
			t.Fatalf("esperava ErrTokenTooLarge, obteve: %v", err)
		}
	})

	t.Run("RS256 MaxTokenLen zero nao limita", func(t *testing.T) {
		_, err := jwt.VerifyRS256WithOptions(rsToken, &privateKey.PublicKey, jwt.VerifyOptions{
			MaxTokenLen: 0,
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
	})

	t.Run("RS256 token vazio", func(t *testing.T) {
		_, err := jwt.VerifyRS256WithOptions("", &privateKey.PublicKey, jwt.VerifyOptions{})
		if !errors.Is(err, jwt.ErrInvalidToken) {
			t.Fatalf("esperava ErrInvalidToken, obteve: %v", err)
		}
	})
}

// TestVerifyWithOptions_Revocation valida denylist por jti em HS256 e RS256.
func TestVerifyWithOptions_Revocation(t *testing.T) {
	revoked := map[string]bool{"dead-token": true}
	store := jwt.RevocationFunc(func(jti string) bool {
		return revoked[jti]
	})

	t.Run("HS256 token revogado", func(t *testing.T) {
		token, err := jwt.SignHS256(jwt.Claims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": "dead-token",
		}, testSecret)
		if err != nil {
			t.Fatalf("SignHS256: %v", err)
		}
		_, err = jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			RevocationStore: store,
		})
		if !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Fatalf("esperava ErrTokenRevoked, obteve: %v", err)
		}
	})

	t.Run("HS256 token ativo com store", func(t *testing.T) {
		token, err := jwt.SignHS256(jwt.Claims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": "live-token",
		}, testSecret)
		if err != nil {
			t.Fatalf("SignHS256: %v", err)
		}
		parsed, err := jwt.VerifyHS256WithOptions(token, testSecret, jwt.VerifyOptions{
			RevocationStore: store,
		})
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if id, ok := parsed.ID(); !ok || id != "live-token" {
			t.Fatalf("jti = %q, ok=%v", id, ok)
		}
	})

	t.Run("RS256 token revogado", func(t *testing.T) {
		privateKey := generateRSAKey(t)
		token, err := jwt.SignRS256(jwt.Claims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": "dead-token",
		}, privateKey)
		if err != nil {
			t.Fatalf("SignRS256: %v", err)
		}
		_, err = jwt.VerifyRS256WithOptions(token, &privateKey.PublicKey, jwt.VerifyOptions{
			RevocationStore: store,
		})
		if !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Fatalf("esperava ErrTokenRevoked, obteve: %v", err)
		}
	})
}

type customClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func TestVerifyHS256As_TypedRoundTrip(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	in := customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "issuer",
			Audience:  jwt.Audience{"api"},
			ExpiresAt: exp,
			ID:        "jti-1",
		},
		Role: "admin",
	}

	token, err := jwt.SignHS256(in, testSecret)
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}

	parsed, err := jwt.VerifyHS256As[customClaims](token, testSecret, jwt.VerifyOptions{
		Issuer:   "issuer",
		Audience: "api",
	})
	if err != nil {
		t.Fatalf("VerifyHS256As: %v", err)
	}
	if parsed.Role != "admin" {
		t.Fatalf("Role = %q", parsed.Role)
	}
	if parsed.Subject != "user-1" || parsed.Issuer != "issuer" || parsed.ID != "jti-1" {
		t.Fatalf("RegisteredClaims = %+v", parsed.RegisteredClaims)
	}
	if parsed.ExpiresAt != exp {
		t.Fatalf("ExpiresAt = %d, want %d", parsed.ExpiresAt, exp)
	}
	if len(parsed.Audience) != 1 || parsed.Audience[0] != "api" {
		t.Fatalf("Audience = %#v", parsed.Audience)
	}
}

func TestVerifyRS256As_TypedRoundTrip(t *testing.T) {
	privateKey := generateRSAKey(t)
	exp := time.Now().Add(time.Hour).Unix()
	in := customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-rs",
			ExpiresAt: exp,
		},
		Role: "editor",
	}

	token, err := jwt.SignRS256(in, privateKey)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}

	parsed, err := jwt.VerifyRS256As[customClaims](token, &privateKey.PublicKey, jwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyRS256As: %v", err)
	}
	if parsed.Role != "editor" || parsed.Subject != "user-rs" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestVerifyHS256As_ClaimsSmoke(t *testing.T) {
	token, err := jwt.SignHS256(jwt.Claims{
		"sub": "map-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, testSecret)
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}

	asMap, err := jwt.VerifyHS256As[jwt.Claims](token, testSecret, jwt.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyHS256As[Claims]: %v", err)
	}
	legacy, err := jwt.VerifyHS256(token, testSecret)
	if err != nil {
		t.Fatalf("VerifyHS256: %v", err)
	}
	if asMap["sub"] != legacy["sub"] {
		t.Fatalf("sub As=%v legacy=%v", asMap["sub"], legacy["sub"])
	}
}

func TestVerifyHS256As_AudienceStringAndArray(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()

	t.Run("aud string", func(t *testing.T) {
		token := signedTokenWithHeader(t, map[string]string{"alg": "HS256", "typ": "JWT"}, jwt.Claims{
			"exp": exp,
			"aud": "api",
		}, testSecret)
		parsed, err := jwt.VerifyHS256As[customClaims](token, testSecret, jwt.VerifyOptions{Audience: "api"})
		if err != nil {
			t.Fatalf("VerifyHS256As: %v", err)
		}
		if len(parsed.Audience) != 1 || parsed.Audience[0] != "api" {
			t.Fatalf("Audience = %#v", parsed.Audience)
		}
	})

	t.Run("aud array", func(t *testing.T) {
		token := signedTokenWithHeader(t, map[string]string{"alg": "HS256", "typ": "JWT"}, jwt.Claims{
			"exp": exp,
			"aud": []string{"web", "api"},
		}, testSecret)
		parsed, err := jwt.VerifyHS256As[customClaims](token, testSecret, jwt.VerifyOptions{Audience: "api"})
		if err != nil {
			t.Fatalf("VerifyHS256As: %v", err)
		}
		if len(parsed.Audience) != 2 {
			t.Fatalf("Audience = %#v", parsed.Audience)
		}
	})
}

func TestVerifyHS256As_Expired(t *testing.T) {
	t.Run("exp ausente", func(t *testing.T) {
		token, err := jwt.SignHS256(customClaims{Role: "x"}, testSecret)
		if err != nil {
			t.Fatalf("SignHS256: %v", err)
		}
		_, err = jwt.VerifyHS256As[customClaims](token, testSecret, jwt.VerifyOptions{})
		if !errors.Is(err, jwt.ErrExpiredToken) {
			t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
		}
	})

	t.Run("exp no passado", func(t *testing.T) {
		token, err := jwt.SignHS256(customClaims{
			RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: time.Now().Add(-time.Hour).Unix()},
			Role:             "x",
		}, testSecret)
		if err != nil {
			t.Fatalf("SignHS256: %v", err)
		}
		_, err = jwt.VerifyHS256As[customClaims](token, testSecret, jwt.VerifyOptions{})
		if !errors.Is(err, jwt.ErrExpiredToken) {
			t.Fatalf("esperava ErrExpiredToken, obteve: %v", err)
		}
	})
}
