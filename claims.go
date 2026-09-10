package jwt

import (
	"time"
)

// VerifyOptions configura validações opcionais de claims na verificação.
// Issuer/Audience vazios e MaxAge/MaxTokenLen zero significam que a validação correspondente não é exigida.
// EnableClockSkew false ignora ClockSkew; negativos em ClockSkew são tratados como zero.
// RevocationStore nil desativa a checagem de revogação por "jti".
type VerifyOptions struct {
	Issuer          string          // valor esperado de "iss"; vazio = não validar
	Audience        string          // valor esperado de "aud"; vazio = não validar
	MaxAge          time.Duration   // idade máxima desde "iat"; 0 = não validar
	ClockSkew       time.Duration   // tolerância de desvio de clock em exp/nbf/iat
	EnableClockSkew bool            // se true, aplica ClockSkew; se false, sem folga
	MaxTokenLen     int             // tamanho máximo do token em bytes; 0 = não validar
	RevocationStore RevocationStore // nil = não checar revogação; exige "jti" presente para consultar
}

// Claims representa o payload de um JWT como um mapa de chave-valor.
type Claims map[string]interface{}

// HasIssuer verifica se o token possui a claim "iss" (Issuer).
func (c Claims) HasIssuer(expected string) bool {
	iss, ok := c.stringClaim("iss")
	return ok && iss == expected
}

// IssuedAt extrai o timestamp Unix da claim "iat" (Issued At).
func (c Claims) IssuedAt() (int64, bool) {
	return c.extractTime("iat")
}

// HasAudience verifica se o token possui a claim "aud" (Audience).
func (c Claims) HasAudience(expected string) bool {
	rawAud, ok := c["aud"]
	if !ok {
		return false
	}

	switch v := rawAud.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, aud := range v {
			if audStr, ok := aud.(string); ok && audStr == expected {
				return true
			}
		}
	}
	return false
}

// HasValidExp informa se "exp" está presente, é parseável e ainda não expirou.
// Na borda now == exp o token já é considerado inválido (now >= exp).
func (c Claims) HasValidExp() bool {
	return c.hasValidExpAt(time.Now().Unix())
}

func (c Claims) hasValidExpAt(now int64) bool {
	exp, ok := c.extractTime("exp")
	if !ok {
		return false
	}
	return now < exp
}

// IsValidNbf informa se "nbf" está ausente ou se now >= nbf.
// Se "nbf" estiver no futuro, retorna false.
func (c Claims) IsValidNbf() bool {
	return c.isValidNbfAt(time.Now().Unix())
}

func (c Claims) isValidNbfAt(now int64) bool {
	if nbf, ok := c.extractTime("nbf"); ok {
		if now < nbf {
			return false
		}
	}
	return true
}

func (c Claims) extractTime(key string) (int64, bool) {
	rawValue, ok := c[key]
	if !ok {
		return 0, false
	}
	switch v := rawValue.(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}

func (c Claims) stringClaim(key string) (string, bool) {
	raw, ok := c[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

// ID extrai a claim "jti" (JWT ID) do payload
func (c Claims) ID() (string, bool) {
	return c.stringClaim("jti")
}

// Validate verifica exp, nbf e, quando preenchidos em opts, iss, aud e MaxAge (via iat).
// Com EnableClockSkew, ClockSkew aplica tolerância truncada em segundos a exp, nbf,
// iat futuro e MaxAge.
// Com RevocationStore, se "jti" estiver presente e IsRevoked retornar true, retorna ErrTokenRevoked.
// Sem "jti" (ou tipo inválido), a checagem de revogação é ignorada.
// Retorna ErrExpiredToken, ErrInvalidNotBefore, ErrInvalidIssuer, ErrInvalidAudience,
// ErrInvalidIssuedAt, ErrInvalidMaxAge ou ErrTokenRevoked.
func (c Claims) Validate(opts VerifyOptions) error {
	now := time.Now().Unix()
	var skew int64
	if opts.EnableClockSkew {
		skew = int64(opts.ClockSkew / time.Second)
		if skew < 0 {
			skew = 0
		}
	}
	skewDur := time.Duration(skew) * time.Second

	expNow := now - skew
	if expNow < 0 {
		expNow = 0
	}
	if !c.hasValidExpAt(expNow) {
		return ErrExpiredToken
	}

	if !c.isValidNbfAt(now + skew) {
		return ErrInvalidNotBefore
	}

	if opts.Issuer != "" && !c.HasIssuer(opts.Issuer) {
		return ErrInvalidIssuer
	}
	if opts.Audience != "" && !c.HasAudience(opts.Audience) {
		return ErrInvalidAudience
	}

	if opts.MaxAge > 0 {
		iat, ok := c.IssuedAt()
		if !ok {
			return ErrInvalidIssuedAt
		}

		if iat > now+skew {
			return ErrInvalidIssuedAt
		}

		age := time.Duration(now-iat) * time.Second
		// idade == MaxAge+ClockSkew ainda é aceita (comparação estrita)
		if age > opts.MaxAge+skewDur {
			return ErrInvalidMaxAge
		}
	}

	if opts.RevocationStore != nil {
		if jti, ok := c.ID(); ok && opts.RevocationStore.IsRevoked(jti) {
			return ErrTokenRevoked
		}
	}
	return nil
}
