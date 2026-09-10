package jwt

import "errors"

// Erros retornados pelas operações de assinatura e verificação de tokens.
var (
	// ErrWeakSecret indica que o secret é muito fraco.
	ErrWeakSecret = errors.New("jwt: secret deve ter no mínimo 32 bytes")
	// ErrInvalidToken indica que o token está malformado ou não pôde ser decodificado.
	ErrInvalidToken = errors.New("jwt: token malformado ou inválido")

	// ErrTokenTooLarge indica que o token excede opts.MaxTokenLen.
	ErrTokenTooLarge = errors.New("jwt: token excede o tamanho máximo permitido")

	// ErrExpiredToken indica que o token expirou ou não possui claim "exp" válida.
	ErrExpiredToken = errors.New("jwt: token expirado")

	// ErrInvalidSignature indica que a assinatura do token não confere.
	ErrInvalidSignature = errors.New("jwt: assinatura inválida")

	// ErrInvalidIssuer indica que o emissor (iss) do token é inválido.
	ErrInvalidIssuer = errors.New("jwt: emissor inválido")

	// ErrInvalidAudience indica que o público (aud) do token é inválido.
	ErrInvalidAudience = errors.New("jwt: público inválido")

	// ErrInvalidIssuedAt indica que a data de emissão (iat) é inválida.
	ErrInvalidIssuedAt = errors.New("jwt: data de emissão inválida")

	// ErrInvalidNotBefore indica que a data de início de validade (nbf) é inválida.
	ErrInvalidNotBefore = errors.New("jwt: data de inicio de validade inválida")

	// ErrInvalidTokenType indica que o header tem alg ou typ inválidos
	// (ex.: alg diferente de "HS256", ou typ presente e diferente de "JWT").
	ErrInvalidTokenType = errors.New("jwt: tipo de token inválido")

	// ErrInvalidHeader indica que o header é inválido.
	ErrInvalidHeader = errors.New("jwt: header inválido ou não pôde ser serializado")

	// ErrInvalidPayload indica que o payload é inválido.
	ErrInvalidPayload = errors.New("jwt: payload inválido ou não pôde ser serializado")

	// ErrInvalidMaxAge indica que o token foi emitido a mais tempo atrás do que o esperado.
	ErrInvalidMaxAge = errors.New("jwt: token emitido a mais tempo atrás do que o esperado")

	// ErrTokenRevoked indica que o jti do token está na denylist (RevocationStore).
	ErrTokenRevoked = errors.New("jwt: token revogado")
)
