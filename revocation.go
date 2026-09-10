package jwt

// RevocationStore consulta se um JWT ID (claim "jti") foi revogado.
// A lib não persiste nada: o consumidor implementa com Redis, banco, etc.
// nil em VerifyOptions.RevocationStore desativa a checagem.
type RevocationStore interface {
	IsRevoked(jti string) bool
}

// RevocationFunc adapta uma função para RevocationStore (ex.: closure com Redis).
type RevocationFunc func(jti string) bool

// IsRevoked chama a função adaptada.
func (f RevocationFunc) IsRevoked(jti string) bool {
	return f(jti)
}
