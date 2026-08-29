// Package jwt implementa assinatura e verificação de tokens JWT com algoritmo HS256.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Header representa o cabeçalho padrão de um JWT (JOSE).
type Header struct {
	Alg string `json:"alg"` // Algoritmo de assinatura (ex.: "HS256").
	Typ string `json:"typ"` // Tipo do token (sempre "JWT" neste pacote).
}

// SignHS256 cria um token JWT assinado com HMAC-SHA256 usando o secret informado.
// Para que o token seja aceito por VerifyHS256, claims deve incluir "exp" com timestamp Unix válido.
func SignHS256(claims Claims, secret string) (string, error) {
	header := Header{Alg: "HS256", Typ: "JWT"}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", ErrInvalidToken
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", ErrInvalidToken
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signature := computeHMACSHA256(headerBase64+"."+payloadBase64, secret)

	return headerBase64 + "." + payloadBase64 + "." + signature, nil
}

// VerifyHS256 valida a assinatura, a expiração e devolve as claims do payload.
// Retorna ErrInvalidSignature se a assinatura não confere, ErrExpiredToken se
// "exp" estiver ausente, inválido ou no passado, e ErrInvalidToken se o token
// estiver malformado.
func VerifyHS256(token, secret string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerBase64, payloadBase64, signature := parts[0], parts[1], parts[2]

	expectedSignature := computeHMACSHA256(headerBase64+"."+payloadBase64, secret)
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return nil, ErrInvalidSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.IsExpired() {
		return nil, ErrExpiredToken
	}

	return claims, nil

}

// computeHMACSHA256 gera a assinatura HMAC-SHA256 de data usando secret como chave.
func computeHMACSHA256(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
