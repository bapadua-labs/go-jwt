# go-jwt

Biblioteca Go para assinatura e verificação de tokens [JWT](https://jwt.io/) com algoritmo **HS256** (HMAC-SHA256).

Focada em simplicidade e API mínima — ideal para aprendizado, protótipos e projetos que precisam de JWT simétrico sem dependências externas.

## Requisitos

- Go 1.26+

## Instalação

```bash
go get github.com/bapadua-labs/go-jwt
```

## Uso rápido

```go
package main

import (
	"fmt"
	"time"

	"github.com/bapadua-labs/go-jwt"
)

func main() {
	secret := "sua-chave-secreta-com-pelo-menos-32-bytes"

	claims := jwt.Claims{
		"sub": "usuario-123",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	token, err := jwt.SignHS256(claims, secret)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.VerifyHS256(token, secret)
	if err != nil {
		panic(err)
	}

	fmt.Println("subject:", parsed["sub"])
}
```

## API

### Assinatura e verificação

| Função / constante | Descrição |
|--------------------|-----------|
| `SignHS256(claims, secret)` | Cria um token JWT assinado (exige secret ≥ `MinSecretLen`) |
| `VerifyHS256(token, secret)` | Valida secret, assinatura, header (`alg`/`typ`) e expiração, retorna as claims |
| `MinSecretLen` | Tamanho mínimo do secret em bytes (32) |

### Claims

| Método | Descrição |
|--------|-----------|
| `Claims` | `map[string]interface{}` representando o payload |
| `HasValidExp()` | `true` se `exp` existe, é válido e ainda não expirou |
| `IsExpired()` | `true` se `exp` está ausente, inválido ou no passado |

### Erros

| Erro | Quando ocorre |
|------|---------------|
| `ErrWeakSecret` | Secret com menos de 32 bytes em `SignHS256` ou `VerifyHS256` |
| `ErrInvalidToken` | Token malformado ou payload ilegível |
| `ErrInvalidSignature` | Assinatura não confere ou secret incorreto (com tamanho válido) |
| `ErrInvalidTokenType` | `alg` diferente de `HS256`, ou `typ` presente e diferente de `JWT` |
| `ErrExpiredToken` | `exp` ausente, inválido ou expirado |

## Comportamento de `exp`

- `VerifyHS256` **rejeita** tokens sem a claim `exp`.
- `exp` deve ser um timestamp Unix (`int64` ao assinar; `float64` após decodificação JSON).
- Tokens com `exp` no passado retornam `ErrExpiredToken`.

## Segurança

### O que a lib faz

- Assinatura HMAC-SHA256 com comparação timing-safe (`hmac.Equal`)
- Codificação Base64 URL-safe (padrão JWT)
- Validação do header (`alg` = `HS256`; `typ` = `JWT` quando informado)
- Validação automática de expiração em `VerifyHS256`
- Rejeição de secrets com menos de 32 bytes (`MinSecretLen` / `ErrWeakSecret`)

### O que a lib **não** faz ainda

- Validação de `iss`, `aud`, `sub`, `nbf` ou `iat`
- Revogação de tokens ou suporte a `jti`
- Algoritmos assimétricos (RS256, ES256, etc.)
- Criptografia do payload (JWT é assinado, não criptografado)
- Limite de tamanho do token

Consulte o [CHANGELOG](CHANGELOG.md) para o roadmap de melhorias planejadas.

### Boas práticas

- Use secrets fortes e aleatórios (mínimo **obrigatório** na API: 32 bytes)
- Sempre defina `exp` com tempo de vida curto
- Transmita tokens apenas via HTTPS
- Não armazene dados sensíveis no payload

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
