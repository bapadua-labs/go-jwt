package jwt

import "time"

// Claims representa o payload de um JWT como um mapa de chave-valor.
type Claims map[string]interface{}

// IsExpired informa se o token não possui exp válido ou já expirou.
func (c Claims) IsExpired() bool {
	return !c.HasValidExp()
}

// HasValidExp informa se a claim "exp" está presente, é parseável e ainda não expirou.
func (c Claims) HasValidExp() bool {
	expUnix, ok := c.expUnix()
	if !ok {
		return false
	}
	return time.Now().Unix() < expUnix
}

// expUnix extrai o timestamp Unix da claim "exp" quando presente e parseável.
func (c Claims) expUnix() (int64, bool) {
	rawExp, ok := c["exp"]
	if !ok {
		return 0, false
	}
	switch v := rawExp.(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}
