# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Planejado

- Exigir `exp` em `SignHS256` / `SignRS256`

## [1.0.0] - 2026-09-09

Lançamento inicial da API pública (stdlib-only).

### Adicionado

#### Assinatura e verificação

- `SignHS256[T]` / `VerifyHS256` / `VerifyHS256WithOptions` / `VerifyHS256As[T]` (HMAC-SHA256)
- `SignRS256[T]` / `VerifyRS256` / `VerifyRS256WithOptions` / `VerifyRS256As[T]` (RSA-SHA256, PKCS#1 v1.5)
- `MinSecretLen` (32) e `ErrWeakSecret` para secrets HMAC curtos
- `Algorithm` / `AlgorithmHS256` / `AlgorithmRS256` com `Valid()` e `String()`
- `Header` com `alg` e `typ`
- `VerifyOptions`: `Issuer`, `Audience`, `MaxAge`, `MaxTokenLen`, `EnableClockSkew`, `ClockSkew`, `RevocationStore`

#### Claims

- `Claims` (`map[string]interface{}`) com `HasIssuer`, `HasAudience`, `HasValidExp`, `IsValidNbf`, `IssuedAt`, `ID`, `Validate`
- `RegisteredClaims` embutível (`iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti`) e `Validate` delegando a `Claims.Validate`
- `Audience` — `aud` como string ou array JSON

#### Revogação

- `RevocationStore` (`IsRevoked(jti string) bool`)
- `RevocationFunc` — adapter de função
- `ErrTokenRevoked` quando o store indica revogação

#### Erros

- `ErrInvalidToken`, `ErrTokenTooLarge`, `ErrInvalidSignature`, `ErrInvalidTokenType`
- `ErrInvalidHeader`, `ErrInvalidPayload`
- `ErrExpiredToken`, `ErrInvalidNotBefore`, `ErrInvalidIssuer`, `ErrInvalidAudience`
- `ErrInvalidIssuedAt`, `ErrInvalidMaxAge`, `ErrTokenRevoked`, `ErrWeakSecret`

### Segurança

- Comparação de assinatura HMAC com `hmac.Equal` (timing-safe)
- Codificação Base64 URL-safe
- Validação de header (`alg` esperado; `typ` = `JWT` quando informado)
- Rejeição automática de `exp` ausente/expirado e `nbf` no futuro em `Verify*`
- Rejeição de confusão de algoritmo entre HS256 e RS256

[Unreleased]: https://github.com/bapadua-labs/go-jwt/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bapadua-labs/go-jwt/releases/tag/v1.0.0
