// Package jwt implementa assinatura e verificação de tokens JWT com HS256 e RS256.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Header representa o cabeçalho padrão de um JWT (JOSE).
type Header struct {
	Alg Algorithm `json:"alg"` // Algoritmo de assinatura (ex.: "HS256").
	Typ string    `json:"typ"` // Tipo do token ("JWT" ao assinar; na verificação, vazio também é aceito).
}

// MinSecretLen é o tamanho mínimo em bytes exigido para o secret HMAC (HS256).
const MinSecretLen = 32

// SignHS256 cria um token JWT assinado com HMAC-SHA256 usando o secret informado.
// claims pode ser Claims (mapa) ou qualquer struct serializável em JSON (ex.: RegisteredClaims).
// Para que o token seja aceito por VerifyHS256, claims deve incluir "exp" com timestamp Unix válido.
// Retorna ErrWeakSecret se o secret tiver menos de MinSecretLen bytes,
// ErrInvalidHeader ou ErrInvalidPayload se header/payload não puderem ser serializados.
func SignHS256[T any](claims T, secret string) (string, error) {
	if err := validateSecret(secret); err != nil {
		return "", err
	}

	unsignedToken, err := encodeUnsignedToken(AlgorithmHS256, claims)
	if err != nil {
		return "", err
	}

	signature := computeHMACSHA256(unsignedToken, secret)
	return unsignedToken + "." + signature, nil
}

// VerifyHS256 valida assinatura, header (alg/typ), exp e nbf (quando presente).
// Equivale a VerifyHS256WithOptions com VerifyOptions vazio (não exige iss/aud/MaxAge/MaxTokenLen).
// Retorna ErrWeakSecret, ErrInvalidSignature, ErrInvalidTokenType, ErrExpiredToken,
// ErrInvalidNotBefore ou ErrInvalidToken conforme o caso.
func VerifyHS256(token, secret string) (Claims, error) {
	return VerifyHS256WithOptions(token, secret, VerifyOptions{})
}

// VerifyHS256WithOptions é como VerifyHS256, e ainda valida Issuer, Audience, MaxAge
// (via iat), MaxTokenLen, ClockSkew (quando EnableClockSkew) e RevocationStore
// (quando não-nil e "jti" presente) preenchidos em opts.
// Token vazio retorna ErrInvalidToken antes da validação do secret.
func VerifyHS256WithOptions(token, secret string, opts VerifyOptions) (Claims, error) {
	return VerifyHS256As[Claims](token, secret, opts)
}

// VerifyHS256As é como VerifyHS256WithOptions, mas deserializa o payload para T
// (ex.: struct com RegisteredClaims embutido). Use VerifyHS256 / VerifyHS256WithOptions
// quando quiser o mapa Claims.
func VerifyHS256As[T any](token, secret string, opts VerifyOptions) (T, error) {
	var zero T
	if err := enforceTokenConstraints(token, opts); err != nil {
		return zero, err
	}

	if err := validateSecret(secret); err != nil {
		return zero, err
	}

	headerBase64, payloadBase64, signature, err := splitToken(token)
	if err != nil {
		return zero, err
	}

	expectedSignature := computeHMACSHA256(headerBase64+"."+payloadBase64, secret)
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return zero, ErrInvalidSignature
	}

	if err := validateHeader(headerBase64, AlgorithmHS256); err != nil {
		return zero, err
	}

	return parseAndValidateClaims[T](payloadBase64, opts)
}

// enforceTokenConstraints rejeita token vazio e, se MaxTokenLen > 0, tokens maiores que o limite.
// len(token) == MaxTokenLen ainda é aceito. MaxTokenLen <= 0 desativa o limite.
func enforceTokenConstraints(token string, opts VerifyOptions) error {
	if len(token) == 0 {
		return ErrInvalidToken
	}
	if opts.MaxTokenLen > 0 && len(token) > opts.MaxTokenLen {
		return ErrTokenTooLarge
	}
	return nil
}

// splitToken separa um JWT em header, payload e assinatura (Base64 URL-safe).
func splitToken(token string) (header, payload, signature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", ErrInvalidToken
	}
	return parts[0], parts[1], parts[2], nil
}

// parseAndValidateClaims decodifica o payload, valida via Claims.Validate e unmarshala em T.
func parseAndValidateClaims[T any](payloadBase64 string, opts VerifyOptions) (T, error) {
	var zero T
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return zero, ErrInvalidToken
	}

	var mapClaims Claims
	if err := json.Unmarshal(payloadBytes, &mapClaims); err != nil {
		return zero, ErrInvalidToken
	}
	if err := mapClaims.Validate(opts); err != nil {
		return zero, err
	}

	var claims T
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return zero, ErrInvalidToken
	}
	return claims, nil
}

// validateSecret verifica se o secret tem pelo menos MinSecretLen bytes.
func validateSecret(secret string) error {
	if len(secret) < MinSecretLen {
		return ErrWeakSecret
	}
	return nil
}

// validateHeader decodifica o header JWT e rejeita algoritmos/tipos não suportados.
// Aceita tipicamente apenas alg "HS256"; typ, se presente, deve ser "JWT".
func validateHeader(headerBase64 string, expectedAlg Algorithm) error {
	if !expectedAlg.Valid() {
		return ErrInvalidTokenType
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerBase64)
	if err != nil {
		return ErrInvalidToken
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return ErrInvalidToken
	}

	if header.Alg != expectedAlg {
		return ErrInvalidTokenType
	}

	if header.Typ != "" && header.Typ != "JWT" {
		return ErrInvalidTokenType
	}

	return nil
}

// computeHMACSHA256 gera a assinatura HMAC-SHA256 de data usando secret como chave.
func computeHMACSHA256(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SignRS256 gera um token assinado usando uma chave privada RSA.
// claims pode ser Claims (mapa) ou qualquer struct serializável em JSON.
// Retorna ErrInvalidHeader ou ErrInvalidPayload se header/payload não puderem ser serializados.
func SignRS256[T any](claims T, privateKey *rsa.PrivateKey) (string, error) {
	unsignedToken, err := encodeUnsignedToken(AlgorithmRS256, claims)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write([]byte(unsignedToken))
	hashed := hasher.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", ErrInvalidSignature
	}

	signatureBase64 := base64.RawURLEncoding.EncodeToString(signatureBytes)
	return unsignedToken + "." + signatureBase64, nil
}

// encodeUnsignedToken serializa header+payload e retorna "header.payload" em Base64 URL-safe.
func encodeUnsignedToken(alg Algorithm, claims any) (string, error) {
	header := Header{Alg: alg, Typ: "JWT"}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", ErrInvalidHeader
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", ErrInvalidPayload
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return headerBase64 + "." + payloadBase64, nil
}

// VerifyRS256 valida assinatura RSA, header (alg/typ), exp e nbf (quando presente).
// Equivale a VerifyRS256WithOptions com VerifyOptions vazio (não exige iss/aud/MaxAge/MaxTokenLen).
func VerifyRS256(token string, publicKey *rsa.PublicKey) (Claims, error) {
	return VerifyRS256WithOptions(token, publicKey, VerifyOptions{})
}

// VerifyRS256WithOptions é como VerifyRS256, e ainda valida Issuer, Audience, MaxAge
// (via iat), MaxTokenLen, ClockSkew (quando EnableClockSkew) e RevocationStore
// (quando não-nil e "jti" presente) preenchidos em opts.
// Token vazio retorna ErrInvalidToken.
func VerifyRS256WithOptions(token string, publicKey *rsa.PublicKey, opts VerifyOptions) (Claims, error) {
	return VerifyRS256As[Claims](token, publicKey, opts)
}

// VerifyRS256As é como VerifyRS256WithOptions, mas deserializa o payload para T
// (ex.: struct com RegisteredClaims embutido). Use VerifyRS256 / VerifyRS256WithOptions
// quando quiser o mapa Claims.
func VerifyRS256As[T any](token string, publicKey *rsa.PublicKey, opts VerifyOptions) (T, error) {
	var zero T
	if err := enforceTokenConstraints(token, opts); err != nil {
		return zero, err
	}

	headerBase64, payloadBase64, signatureBase64, err := splitToken(token)
	if err != nil {
		return zero, err
	}

	if err := validateHeader(headerBase64, AlgorithmRS256); err != nil {
		return zero, err
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return zero, ErrInvalidToken
	}

	unsignedToken := headerBase64 + "." + payloadBase64
	hasher := sha256.New()
	hasher.Write([]byte(unsignedToken))
	hashed := hasher.Sum(nil)

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signatureBytes); err != nil {
		return zero, ErrInvalidSignature
	}

	return parseAndValidateClaims[T](payloadBase64, opts)
}
