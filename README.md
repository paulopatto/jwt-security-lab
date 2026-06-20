# JWT Security Lab

Laboratório prático de segurança com JSON Web Tokens (JWT). Este projeto demonstra vulnerabilidades comuns em middlewares JWT e como mitigá-las em produção.

## Funcionalidades

- **Rota insegura** (`/dados-inseguros`): middleware JWT básico, sem validação de algoritmo, claims ou revogação
- **Rota segura** (`/dados-sensiveis`): middleware com as 7 boas práticas de segurança
- **Testes automatizados** que provam as vulnerabilidades e as defesas

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/)
- Ou [Node.js](https://nodejs.org/) 20.x localmente

## Como rodar

### Com Docker (recomendado — sem instalar nada na máquina)

```bash
docker compose up -d
```

A API estará disponível em `http://localhost:3000`.

#### Comandos úteis

```bash
# Executar os testes
docker compose exec api npm test

# Ver logs da aplicação
docker compose logs -f api

# Parar os serviços
docker compose down
```

### Sem Docker (Node.js local)

```bash
# Instalar dependências
npm install

# Subir Redis (exemplo com Docker apenas para o Redis)
docker run -d -p 6379:6379 redis:7-alpine

# Rodar em modo dev
npm run dev

# Rodar testes
npm test
```

## Endpoints

| Método | Rota                | Middleware        | Descrição                            |
|--------|---------------------|-------------------|--------------------------------------|
| POST   | `/login`            | rate limit        | Autentica e retorna um JWT           |
| GET    | `/dados-inseguros`  | inseguro          | Aceita qualquer token com assinatura |
| GET    | `/dados-sensiveis`  | seguro            | Exige claims e blacklist             |
| POST   | `/logout`           | seguro            | Revoga o token (blacklist no Redis)  |

## Credenciais de teste

- Usuário: `admin`
- Senha: `1234`

## Estrutura

```
jwt-lab/
├── src/
│   └── server.ts          # Servidor Express com middlewares seguro e inseguro
├── test/
│   └── security.test.ts   # Testes comparando vulnerabilidade vs defesa
├── compose.yml            # Docker Compose com API + Redis
└── package.json           # Dependências e scripts
```

## Licença

MIT

## Créditos

Inspirado no post do linkedin de [@Lucas Albuquerque](https://www.linkedin.com/in/lucasalbuquerquecode/) [sobre falhas de segurança em JWT em middlewares de produção](https://www.linkedin.com/posts/lucasalbuquerquecode_a-maioria-dos-middlewares-de-jwt-que-vejo-share-7473321266813440000-CSrj)
