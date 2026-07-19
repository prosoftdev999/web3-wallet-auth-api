# Web3 Wallet Authentication API

A production-ready FastAPI backend that authenticates users using Ethereum wallets with Sign-In with Ethereum (SIWE).

## Features

- 🔐 Sign-In with Ethereum (SIWE)
- 🎲 Secure nonce generation
- 👛 Wallet signature verification
- 🔑 JWT authentication
- 👤 Protected user profile endpoint
- 🚪 Logout endpoint
- 🐘 PostgreSQL database
- ⚡ Redis nonce storage
- 🐳 Docker & Docker Compose
- 🔄 Alembic database migrations
- ✅ Pytest test suite
- 🚀 GitHub Actions CI

---

## Tech Stack

- Python 3.12
- FastAPI
- SQLAlchemy (Async)
- PostgreSQL
- Redis
- Alembic
- JWT
- eth-account
- Docker
- GitHub Actions
- Pytest

---

## Project Structure

```
.
├── app/
│   ├── api/
│   ├── core/
│   ├── db/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   └── main.py
├── alembic/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── alembic.ini
└── README.md
```

---

## Requirements

- Docker
- Docker Compose

or

- Python 3.12
- PostgreSQL
- Redis

---

## Installation

Clone the repository

```bash
git clone https://github.com/prosoftdev999/web3-wallet-auth-api.git

cd web3-wallet-auth-api
```

---

## Environment Variables

Copy the example environment file.

```bash
cp .env.example .env
```

Configure your values inside `.env`.

---

## Running with Docker

Build containers

```bash
docker compose build
```

Start services

```bash
docker compose up -d
```

Check containers

```bash
docker compose ps
```

---

## Run Database Migrations

```bash
docker compose exec api alembic upgrade head
```

---

## API Documentation

Swagger UI

```
http://localhost:8001/docs
```

OpenAPI

```
http://localhost:8001/openapi.json
```

Health Check

```
http://localhost:8001/health
```

---

## Authentication Flow

### 1. Request Nonce

```
POST /auth/nonce
```

Example

```json
{
  "wallet_address": "0x..."
}
```

---

### 2. Sign SIWE Message

Sign the returned SIWE message using your Ethereum wallet.

---

### 3. Login

```
POST /auth/login
```

```json
{
  "message": "...",
  "signature": "0x..."
}
```

Returns

```json
{
  "access_token": "...",
  "token_type": "bearer"
}
```

---

### 4. Get Current User

```
GET /me
```

Authorization

```
Bearer <access_token>
```

---

### 5. Logout

```
POST /auth/logout
```

---

## Running Tests

```bash
pytest -v
```

Expected output

```
6 passed
```

---

## GitHub Actions

Continuous Integration automatically:

- installs dependencies
- builds Docker image
- starts PostgreSQL
- starts Redis
- runs migrations
- verifies API routes
- executes all tests

---

## Docker Commands

Start

```bash
docker compose up -d
```

Stop

```bash
docker compose down
```

Rebuild

```bash
docker compose build --no-cache
```

Logs

```bash
docker compose logs
```

---

## License

MIT License

---

## Author

**Johan Bergman**

GitHub

https://github.com/prosoftdev999

---

## Repository

https://github.com/prosoftdev999/web3-wallet-auth-api