package jwt

import (
	"encoding/json"
)

// Audience representa a claim "aud" como uma ou mais audiências.
// Aceita JSON string ou array de strings (paridade com Claims.HasAudience).
type Audience []string

// MarshalJSON serializa uma audiência única como string e múltiplas como array.
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte("null"), nil
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

// UnmarshalJSON aceita "aud" como string ou array de strings.
func (a *Audience) UnmarshalJSON(data []byte) error {
	if a == nil {
		return nil
	}
	if string(data) == "null" {
		*a = nil
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = Audience(many)
	return nil
}

// RegisteredClaims agrupa as claims JWT registradas para embedding em structs tipadas.
type RegisteredClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"` // Unix; 0 = ausente
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
}

// toClaims converte RegisteredClaims para Claims (mapa) para reutilizar Validate.
func (c RegisteredClaims) toClaims() Claims {
	claims := Claims{}
	if c.Issuer != "" {
		claims["iss"] = c.Issuer
	}
	if c.Subject != "" {
		claims["sub"] = c.Subject
	}
	switch len(c.Audience) {
	case 0:
		// omitido
	case 1:
		claims["aud"] = c.Audience[0]
	default:
		aud := make([]interface{}, len(c.Audience))
		for i, v := range c.Audience {
			aud[i] = v
		}
		claims["aud"] = aud
	}
	if c.ExpiresAt != 0 {
		claims["exp"] = c.ExpiresAt
	}
	if c.NotBefore != 0 {
		claims["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		claims["iat"] = c.IssuedAt
	}
	if c.ID != "" {
		claims["jti"] = c.ID
	}
	return claims
}

// Validate aplica as mesmas regras de Claims.Validate (fonte única de verdade).
func (c RegisteredClaims) Validate(opts VerifyOptions) error {
	return c.toClaims().Validate(opts)
}
