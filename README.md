# NiceLogin Python SDK

SDK minimalista para NiceLogin. **Zero dependências externas.**

## Instalação

```bash
pip install nicelogin-jwks-python
```

## Uso Rápido

```python
from nicelogin_jwks import NiceLogin, NiceLoginJWKS

# Cliente para operações
client = NiceLogin(api_key="...", api_secret="...", base_url="https://api.v1.nicelogin.com")

# Trocar senha (1 linha)
client.change_password("user@email.com", "senha_atual", "nova_senha")

# Ativar/desativar usuário
client.activate_user("user-uuid")
client.deactivate_user("user-uuid")

# Verificar token JWKS
verifier = NiceLoginJWKS(jwks)
is_valid = verifier.verify_token(token)
payload = verifier.unpack(token)
```

## API

### `NiceLogin(api_key, api_secret=None, base_url="https://api.v1.nicelogin.com")`

Cliente HTTP para operações de autenticação.

| Método | Descrição |
|--------|-----------|
| `request_password_reset(email)` | Solicita token de reset. Retorna `str` |
| `reset_password(email, current_password, new_password, reset_token)` | Reseta senha com token. Retorna `bool` |
| `change_password(email, current_password, new_password)` | Troca senha (solicita token internamente). Retorna `bool` |
| `activate_user(user_id)` | Ativa usuário. Requer `api_secret`. Retorna `bool` |
| `deactivate_user(user_id)` | Desativa usuário. Requer `api_secret`. Retorna `bool` |

### `NiceLoginJWKS(jwks)`

Verificador de tokens JWT RS256.

| Método | Descrição |
|--------|-----------|
| `verify_token(token)` | Retorna `True` se válido, `False` caso contrário |
| `unpack(token, verify=True)` | Extrai payload. Raises `ValueError` se inválido |

## Exemplos

### Reset de Senha

```python
from nicelogin_jwks import NiceLogin

client = NiceLogin(api_key="nicelogin_xxx")

# Opção 1: Em duas etapas
reset_token = client.request_password_reset("user@email.com")
# Envie o token por email para o usuário
client.reset_password("user@email.com", "senha_atual", "nova_senha", reset_token)

# Opção 2: Direto (se usuário sabe a senha atual)
client.change_password("user@email.com", "senha_atual", "nova_senha")
```

### Ativar/Desativar Usuário

```python
from nicelogin_jwks import NiceLogin

# api_secret necessário para essas operações
client = NiceLogin(api_key="nicelogin_xxx", api_secret="secret_xxx")

client.deactivate_user("550e8400-e29b-41d4-a716-446655440000")
client.activate_user("550e8400-e29b-41d4-a716-446655440000")
```

### Verificar Token JWKS

```python
from nicelogin_jwks import NiceLoginJWKS

# Obtenha JWKS de: GET https://api.v1.nicelogin.com/.well-known/jwks/{api_key}
jwks = {"keys": [{"kty": "RSA", "n": "...", "e": "AQAB", "kid": "..."}]}

verifier = NiceLoginJWKS(jwks)

if verifier.verify_token(token):
    payload = verifier.unpack(token)
    print(f"User: {payload['email']}")
```

## Claims do Token

| Campo | Tipo | Descrição |
|-------|------|-----------|
| sub | str | User ID (UUID) |
| email | str | Email do usuário |
| company_id | str | Company ID (UUID) |
| exp | int | Timestamp de expiração |
| iat | int | Timestamp de emissão |
| jti | str | JWT ID único |
| sid | str? | Session ID (opcional) |
| user_data | dict? | Dados customizados (opcional) |

## Erros

```python
from nicelogin_jwks import NiceLogin, NiceLoginError

client = NiceLogin(api_key="...")

try:
    client.change_password("user@email.com", "wrong", "new")
except NiceLoginError as e:
    print(f"Erro {e.status}: {e.message}")
```

## Licença

MIT
