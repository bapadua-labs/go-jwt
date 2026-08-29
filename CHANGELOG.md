# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.0.0] - 2026-08-29

### Adicionado

- `SignHS256` — assinatura de tokens JWT com HMAC-SHA256
- `VerifyHS256` — verificação de assinatura e expiração
- Tipo `Claims` (`map[string]interface{}`) para o payload do token
- `Claims.HasValidExp()` — verifica se `exp` é válido e ainda não expirou
- `Claims.IsExpired()` — verifica se o token não possui `exp` válido ou já expirou
- Tipo `Header` com campos `alg` e `typ`
- Erros exportados: `ErrInvalidToken`, `ErrExpiredToken`, `ErrInvalidSignature` e demais erros de validação de claims reservados para versões futuras
- Testes de integração (caixa-preta) para fluxo completo de assinatura e verificação
- Testes de segurança: token expirado, sem `exp`, `exp` inválido, assinatura adulterada, secret incorreto e token malformado
- Testes unitários para `HasValidExp` e `IsExpired`
- Documentação Go (`go doc`) em todos os símbolos exportados

### Segurança

- Comparação de assinatura com `hmac.Equal` (timing-safe)
- Codificação Base64 URL-safe consistente entre assinatura e verificação
- Rejeição automática de tokens sem `exp` ou com `exp` expirado em `VerifyHS256`

## [Unreleased]

### Planejado

- Validação de tamanho mínimo do secret
- Exigir `exp` em `SignHS256`
- Limite de tamanho do token
- Validação do header (`alg`, `typ`)
- Suporte a `nbf` (not before)
- Tolerância de clock skew
- API `VerifyWithOptions` para validação de `iss` e `aud`

[1.0.0]: https://github.com/bapadua-labs/go-jwt/releases/tag/v1.0.0
[Unreleased]: https://github.com/bapadua-labs/go-jwt/compare/v1.0.0...HEAD
