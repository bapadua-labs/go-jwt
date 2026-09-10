# go-jwt

Biblioteca Go para assinatura e verificação de tokens [JWT](https://jwt.io/) com algoritmos **HS256** (HMAC-SHA256) e **RS256** (RSA-SHA256).

Focada em simplicidade e API mínima — ideal para aprendizado, protótipos e projetos que precisam de JWT sem dependências externas.

## Requisitos

- Go 1.26+

## Instalação

```bash
go get github.com/bapadua-labs/go-jwt
```

## Uso rápido

### HS256

```go
package main

import (
	"fmt"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

type MyClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func main() {
	secret := "sua-chave-secreta-com-pelo-menos-32-bytes"

	token, err := jwt.SignHS256(MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "usuario-123",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
		Role: "admin",
	}, secret)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.VerifyHS256As[MyClaims](token, secret, jwt.VerifyOptions{})
	if err != nil {
		panic(err)
	}

	fmt.Println("subject:", parsed.Subject, "role:", parsed.Role)
}
```

Ainda é possível usar o mapa `jwt.Claims` com `VerifyHS256` se preferir (sem generics).

### RS256

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

type MyClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	token, err := jwt.SignRS256(MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "usuario-123",
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
		Role: "admin",
	}, privateKey)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.VerifyRS256As[MyClaims](token, &privateKey.PublicKey, jwt.VerifyOptions{})
	if err != nil {
		panic(err)
	}

	fmt.Println("subject:", parsed.Subject, "role:", parsed.Role)
}
```

### Com options (`iss` / `aud` / `MaxAge` / `ClockSkew` / `MaxTokenLen` / revogação)

```go
parsed, err := jwt.VerifyHS256WithOptions(token, secret, jwt.VerifyOptions{
	Issuer:          "meu-issuer",
	Audience:        "minha-api",
	MaxAge:          time.Hour,        // exige iat e rejeita se idade > MaxAge
	EnableClockSkew: true,             // liga a tolerância de relógio
	ClockSkew:       30 * time.Second, // folga em exp/nbf/iat
	MaxTokenLen:     8192,             // rejeita token maior que N bytes
	RevocationStore: jwt.RevocationFunc(func(jti string) bool {
		// consulte Redis/DB do seu app; true = revogado
		return false
	}),
})
```

`VerifyRS256WithOptions` segue o mesmo padrão. `Issuer`/`Audience` vazios e `MaxAge`/`MaxTokenLen` zero não são exigidos. `EnableClockSkew` false (padrão) ignora `ClockSkew`. `RevocationStore` nil (padrão) não checa revogação; com store configurado, tokens precisam de `jti` para entrarem na denylist (sem `jti` a checagem é ignorada).

### Revogação (exemplo com Redis)

A lib não conecta a banco: você implementa `IsRevoked` no app. Emita tokens com `jti` único; no logout (ou invalidação), grave o `jti` no Redis com TTL alinhado ao `exp`.

```go
package main

import (
	"context"
	"time"

	"github.com/bapadua-labs/go-jwt"
	"github.com/redis/go-redis/v9"
)

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx := context.Background()

	// No logout: marque o jti como revogado até o token expirar.
	// rdb.Set(ctx, "jwt:revoked:"+jti, "1", time.Until(expTime))

	store := jwt.RevocationFunc(func(jti string) bool {
		n, err := rdb.Exists(ctx, "jwt:revoked:"+jti).Result()
		if err != nil {
			// fail-closed: trate falha de I/O como revogado
			return true
		}
		return n > 0
	})

	type MyClaims struct {
		jwt.RegisteredClaims
	}

	token, err := jwt.SignHS256(MyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "usuario-123",
			ID:        "uuid-unico-do-token",
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
	}, "sua-chave-secreta-com-pelo-menos-32-bytes")
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.VerifyHS256As[MyClaims](token, "sua-chave-secreta-com-pelo-menos-32-bytes", jwt.VerifyOptions{
		RevocationStore: store,
	})
	if err != nil {
		panic(err) // jwt.ErrTokenRevoked se o jti estiver na denylist
	}
	_ = parsed
}
```

Também dá para usar um `struct` que implementa `RevocationStore` em vez de `RevocationFunc`, se preferir encapsular o client Redis.

`SignHS256` / `SignRS256` aceitam qualquer `T` serializável em JSON (mapa `Claims` ou struct). `VerifyHS256` / `Verify*WithOptions` continuam retornando `Claims`; use `VerifyHS256As` / `VerifyRS256As` para o tipo tipado.

## API

### Assinatura e verificação

| Função / constante | Descrição |
|--------------------|-----------|
| `SignHS256(claims, secret)` | Cria um token JWT assinado com HMAC-SHA256 (exige secret ≥ `MinSecretLen`); `claims` pode ser `Claims` ou struct |
| `VerifyHS256(token, secret)` | Valida secret, assinatura, header, `exp` e `nbf` (se presente); retorna `Claims` |
| `VerifyHS256WithOptions(token, secret, opts)` | Como `VerifyHS256`, e ainda `iss`/`aud`/`MaxAge`/`MaxTokenLen`/`EnableClockSkew`+`ClockSkew`/`RevocationStore` quando preenchidos em `opts` |
| `VerifyHS256As[T](token, secret, opts)` | Como `VerifyHS256WithOptions`, deserializando o payload para `T` |
| `SignRS256(claims, privateKey)` | Cria um token JWT assinado com RSA-SHA256 (PKCS#1 v1.5); `claims` pode ser `Claims` ou struct |
| `VerifyRS256(token, publicKey)` | Valida assinatura RSA, header, `exp` e `nbf` (se presente); retorna `Claims` |
| `VerifyRS256WithOptions(token, publicKey, opts)` | Como `VerifyRS256`, e ainda `iss`/`aud`/`MaxAge`/`MaxTokenLen`/`EnableClockSkew`+`ClockSkew`/`RevocationStore` quando preenchidos em `opts` |
| `VerifyRS256As[T](token, publicKey, opts)` | Como `VerifyRS256WithOptions`, deserializando o payload para `T` |
| `VerifyOptions` | `Issuer`, `Audience`, `MaxAge`, `MaxTokenLen`, `EnableClockSkew`, `ClockSkew` e `RevocationStore` opcionais para as funções `*WithOptions` |
| `RevocationStore` | Interface com `IsRevoked(jti string) bool` — implemente com Redis/DB do app |
| `RevocationFunc` | Adapter de função para `RevocationStore` |
| `MinSecretLen` | Tamanho mínimo do secret HMAC em bytes (32) |
| `Algorithm` / `AlgorithmHS256` / `AlgorithmRS256` | Tipo do algoritmo; `HS256` e `RS256` são válidos |
| `Algorithm.Valid()` | `true` se o algoritmo é suportado |
| `Algorithm.String()` | Valor JOSE do algoritmo (ex.: `"HS256"`, `"RS256"`) |

### Claims

| Método | Descrição |
|--------|-----------|
| `Claims` | `map[string]interface{}` representando o payload |
| `RegisteredClaims` | Struct com `iss`/`sub`/`aud`/`exp`/`nbf`/`iat`/`jti` para embedding em claims tipadas |
| `Audience` | Tipo de `aud` (string ou array JSON); usado em `RegisteredClaims` |
| `RegisteredClaims.Validate(opts)` | Mesmas regras de `Claims.Validate` |
| `ID()` | Extrai a claim `jti` (JWT ID); retorna `(string, bool)` |
| `IssuedAt()` | Extrai a claim `iat` (Issued At); retorna `(int64, bool)` |
| `HasIssuer(expected)` | `true` se `iss` existe, é string e coincide com `expected` |
| `HasAudience(expected)` | `true` se `aud` (string ou array) contém `expected` |
| `HasValidExp()` | `true` se `exp` é válido e ainda não expirou (`now >= exp` já é inválido) |
| `IsValidNbf()` | `true` se `nbf` está ausente ou `now >= nbf` |
| `Validate(opts)` | Valida `exp`/`nbf` (com `ClockSkew` se `EnableClockSkew`) e, se preenchidos, `iss`/`aud`/`MaxAge` (via `iat`) e `RevocationStore` (via `jti`) |

### Erros

| Erro | Quando ocorre |
|------|---------------|
| `ErrWeakSecret` | Secret com menos de 32 bytes em `SignHS256` ou `VerifyHS256` |
| `ErrInvalidToken` | Token malformado, vazio ou payload ilegível |
| `ErrTokenTooLarge` | Token com mais bytes que `opts.MaxTokenLen` (quando `MaxTokenLen > 0`) |
| `ErrInvalidSignature` | Assinatura não confere (HMAC ou RSA) ou secret incorreto (com tamanho válido) |
| `ErrInvalidTokenType` | `alg` diferente do esperado (`HS256`/`RS256`), ou `typ` presente e diferente de `JWT` |
| `ErrInvalidHeader` / `ErrInvalidPayload` | Falha ao serializar header/payload em `SignHS256` ou `SignRS256` |
| `ErrExpiredToken` | `exp` ausente, inválido ou expirado |
| `ErrInvalidNotBefore` | `nbf` no futuro |
| `ErrInvalidIssuer` | `iss` ausente ou diferente do esperado (quando `opts.Issuer` está preenchido) |
| `ErrInvalidAudience` | `aud` ausente ou sem o valor esperado (quando `opts.Audience` está preenchido) |
| `ErrInvalidIssuedAt` | `iat` ausente, inválido ou no futuro além do `ClockSkew` (quando `opts.MaxAge > 0`) |
| `ErrInvalidMaxAge` | idade do token desde `iat` maior que `opts.MaxAge` (+ `ClockSkew` se `EnableClockSkew`) |
| `ErrTokenRevoked` | `jti` presente e `RevocationStore.IsRevoked` retornou `true` |

## Comportamento de tempo

- `VerifyHS256` e `VerifyRS256` **rejeitam** tokens sem `exp` ou com `exp` expirado.
- Também rejeitam `nbf` no futuro, quando a claim está presente.
- `exp`/`nbf`/`iat` devem ser timestamp Unix (`int64` ao assinar; `float64` após decodificação JSON).
- Na borda `now == exp`, o token já é considerado expirado.
- `iss`/`aud` só são exigidos via `Verify*WithOptions` (ou `Claims.Validate`) quando informados em `VerifyOptions`.
- Com `MaxAge > 0`, `iat` é obrigatório; `iat` no futuro ou idade `> MaxAge` invalida o token (idade `== MaxAge` ainda é aceita).
- Com `MaxTokenLen > 0`, tokens com `len > MaxTokenLen` são rejeitados (`len == MaxTokenLen` ainda é aceito).
- Com `EnableClockSkew`, `ClockSkew` aplica folga truncada em segundos a `exp`, `nbf`, `iat` futuro e `MaxAge` (negativo = tratado como 0; toggle desligado ignora o valor).

## Segurança

### O que a lib faz

- Assinatura HMAC-SHA256 com comparação timing-safe (`hmac.Equal`)
- Assinatura RSA-SHA256 (RS256) com chave privada/pública
- Codificação Base64 URL-safe (padrão JWT)
- Validação do header (`alg` esperado; `typ` = `JWT` quando informado)
- Validação automática de `exp` e `nbf` em `Verify*`
- Validação opcional de `iss`/`aud`/`MaxAge` (via `iat`), `MaxTokenLen`, `EnableClockSkew`/`ClockSkew` e `RevocationStore` (via `jti`) via `Verify*WithOptions`
- Rejeição de secrets HMAC com menos de 32 bytes (`MinSecretLen` / `ErrWeakSecret`)
- Rejeição de confusão de algoritmo entre HS256 e RS256
- Helpers para `iss`, `aud`, `nbf`, `iat` e `jti` nas claims
- Revogação via interface `RevocationStore` (sem acoplar Redis/DB na lib)

### O que a lib **não** faz ainda

- Outros algoritmos (ES256, HS384, HS512…)
- Criptografia do payload (JWT é assinado, não criptografado)

Consulte o [CHANGELOG](CHANGELOG.md) para o roadmap de melhorias planejadas.

### Boas práticas

- Em HS256, use secrets fortes e aleatórios (mínimo **obrigatório** na API: 32 bytes)
- Em RS256, proteja a chave privada; distribua só a chave pública para verificação
- Sempre defina `exp` com tempo de vida curto
- Use `Verify*WithOptions` quando precisar de `iss`/`aud`, `MaxAge` (com `iat`), `MaxTokenLen`, `EnableClockSkew`/`ClockSkew` ou `RevocationStore` (com `jti`)
- Transmita tokens apenas via HTTPS
- Não armazene dados sensíveis no payload
- Para revogar tokens, emita com `jti` único e implemente `RevocationStore` no seu app (ex.: Redis)

## Testes

```bash
go test -v ./...
```

## Documentação

```bash
go doc -all github.com/bapadua-labs/go-jwt
```

## Licença

MIT — veja [LICENSE](LICENSE).
