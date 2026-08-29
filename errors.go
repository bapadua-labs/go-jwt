package jwt

import "errors"

// Erros retornados pelas operações de assinatura e verificação de tokens.
var (
	// ErrInvalidToken indica que o token está malformado ou não pôde ser decodificado.
	ErrInvalidToken = errors.New("jwt: token malformado ou inválido")

	// ErrExpiredToken indica que o token expirou ou não possui claim "exp" válida.
	ErrExpiredToken = errors.New("jwt: token expirado")

	// ErrInvalidSignature indica que a assinatura do token não confere.
	ErrInvalidSignature = errors.New("jwt: assinatura inválida")

	// ErrInvalidIssuer indica que o emissor (iss) do token é inválido.
	ErrInvalidIssuer = errors.New("jwt: emissor inválido")

	// ErrInvalidSubject indica que o assunto (sub) do token é inválido.
	ErrInvalidSubject = errors.New("jwt: assunto inválido")

	// ErrInvalidAudience indica que o público (aud) do token é inválido.
	ErrInvalidAudience = errors.New("jwt: público inválido")

	// ErrInvalidIssuedAt indica que a data de emissão (iat) é inválida.
	ErrInvalidIssuedAt = errors.New("jwt: data de emissão inválida")

	// ErrInvalidNotBefore indica que a data de início de validade (nbf) é inválida.
	ErrInvalidNotBefore = errors.New("jwt: data de validade inválida")

	// ErrInvalidExpiresAt indica que a data de expiração (exp) é inválida.
	ErrInvalidExpiresAt = errors.New("jwt: data de expiração inválida")

	// ErrInvalidTokenType indica que o tipo do token é inválido.
	ErrInvalidTokenType = errors.New("jwt: tipo de token inválido")
)
